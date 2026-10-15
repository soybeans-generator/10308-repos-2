// transactions.go

package main

import (
   "bufio"
   "fmt"
   "os"
   "regexp"
   "strconv"
   "strings"
   "time"
)

// matchTarget determines if a transaction should be counted under the given target.
// Special handling: TOM THUMB transactions with a price between $10 and $20
// are reclassified as STARBUCKS.
func matchTarget(txn Transaction, target string) bool {
   // Special case: reclassify TOM THUMB as STARBUCKS if price is $10-$20
   if target == "STARBUCKS" {
      if strings.Contains(txn.Description, "TOM THUMB") {
         amount := -txn.Amount // amount is stored as negative for debits
         if amount >= 10.0 && amount <= 20.0 {
            return true
         }
      }
   }

   // Default matching: check if target is a substring of the description
   return strings.Contains(txn.Description, target)
}

// Transaction holds the parsed date along with the description
type Transaction struct {
   Description string
   Date        time.Time
   Amount      float64
}

// extractRecentTransactions handles file I/O, regex, date parsing, and filtering.
func extractRecentTransactions(filename string, today time.Time, lookbackDays int) ([]Transaction, error) {
   file, err := os.Open(filename)
   if err != nil {
      return nil, fmt.Errorf("failed to open file: %w", err)
   }
   defer file.Close()

   cutoffDate := today.AddDate(0, 0, -lookbackDays)
   var validTransactions []Transaction
   scanner := bufio.NewScanner(file)

   dateRegex := regexp.MustCompile(`\b(\d{2}/\d{2})\b`)
   amountRegex := regexp.MustCompile(`^-?\$?([\d,]+\.\d{2})$`)

   // Buffer to hold description while we wait for the amount
   var pendingDesc string
   var pendingDate time.Time
   var hasPending bool

   for scanner.Scan() {
      line := strings.TrimSpace(scanner.Text())

      switch {
      case line == "Description":
         if scanner.Scan() {
            desc := strings.TrimSpace(scanner.Text())

            match := dateRegex.FindString(desc)
            if match != "" {
               parsedMMDD, err := time.Parse("01/02", match)
               if err == nil {
                  year := today.Year()

                  if parsedMMDD.Month() > today.Month() {
                     year--
                  }

                  parsedDate := time.Date(year, parsedMMDD.Month(), parsedMMDD.Day(), 0, 0, 0, 0, today.Location())

                  if parsedDate.After(cutoffDate) {
                     // Store both the description and the parsed date
                     pendingDesc = desc
                     pendingDate = parsedDate
                     hasPending = true
                  }

               }
            }
         }

      case line == "Amount" && hasPending:
         if scanner.Scan() {
            amountStr := strings.TrimSpace(scanner.Text())
            // Remove $ and , characters
            cleanAmount := strings.ReplaceAll(amountStr, "$", "")
            cleanAmount = strings.ReplaceAll(cleanAmount, ",", "")
            cleanAmount = strings.TrimSpace(cleanAmount)

            if match := amountRegex.FindStringSubmatch(cleanAmount); match != nil {
               if amount, err := strconv.ParseFloat(match[1], 64); err == nil {
                  // Preserve the sign (debits are negative)
                  if strings.HasPrefix(cleanAmount, "-") {
                     amount = -amount
                  }
                  validTransactions = append(validTransactions, Transaction{
                     Description: pendingDesc,
                     Date:        pendingDate,
                     Amount:      amount,
                  })
               }
            }
            hasPending = false
         }
      }
   }

   if err := scanner.Err(); err != nil {
      return nil, fmt.Errorf("error reading file: %w", err)
   }

   return validTransactions, nil
}

// transactions.go
