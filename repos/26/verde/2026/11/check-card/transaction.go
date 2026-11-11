package main

import (
   "bufio"
   "cmp"
   "encoding/csv"
   "flag"
   "fmt"
   "os"
   "regexp"
   "slices"
   "strconv"
   "strings"
   "time"
)

var targets = []Target{
   {Name: "CAFE CREAMSTO"},
   {Name: "CHICK-FIL-A"},
   {Name: "DAVES HOT CHICKEN"},
   {Name: "FIREHOUSE SUBS", Distance: "4.2 mi"},
   {Name: "IN-N-OUT", Distance: "4.1 mi"},
   {Name: "JASON'S DELI"},
   {Name: "JOES COFFEE SHOP"},
   {Name: "LA MADELEINE"},
   {Name: "MCDONALD'S"},
   {Name: "SCHLOTZSKYS"},
   {Name: "SHAKE SHACK"},
   {Name: "SHAWARMA PRESS", Distance: "4.5 mi"},
   {Name: "STARBUCKS"},
   {Name: "TIFF'S TREATS"},
   {Name: "WHATABURGER"},
}

func main() {
   // Define command-line flag for the input file
   inputFile := flag.String("f", "", "Path to the bank statement text file")
   flag.Parse()

   // Ensure the file flag was provided
   if *inputFile == "" {
      flag.Usage()
      os.Exit(1)
   }

   if err := run(*inputFile); err != nil {
      fmt.Fprintf(os.Stderr, "Fatal error: %v\n", err)
      os.Exit(1)
   }
}

// main.go marker preserve
// matchTarget determines if a transaction should be counted under the given target.
func matchTarget(txn Transaction, target string) bool {
   // Default matching: check if target is a substring of the description
   return strings.Contains(txn.Description, target)
}

// run executes the full pipeline: extract transactions, match targets, sort, and write CSV.
func run(filename string) error {
   now := time.Now()
   today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

   // 1. Extract fallible reading logic
   validTransactions, err := extractRecentTransactions(filename, today, 7)
   if err != nil {
      return fmt.Errorf("reading descriptions: %w", err)
   }

   // 2. Count occurrences and track the latest date
   var results []*MatchResult
   for _, target := range targets {
      count := 0
      var lastDate time.Time

      for _, txn := range validTransactions {
         if matchTarget(txn, target.Name) {
            count++
            // Update lastDate if this transaction is more recent
            if txn.Date.After(lastDate) {
               lastDate = txn.Date
            }
         }
      }

      results = append(results, &MatchResult{
         Description: target.Name,
         Distance:    target.Distance,
         Count:       count,
         LastDate:    lastDate,
      })
   }

   // 3. Sort by Count (ascending) THEN Date (ascending)
   slices.SortFunc(results, func(a, b *MatchResult) int {
      // First compare by Count (a vs b for ascending order)
      if countDiff := cmp.Compare(a.Count, b.Count); countDiff != 0 {
         return countDiff
      }
      // If counts are equal, compare by LastDate (a vs b for ascending order)
      return a.LastDate.Compare(b.LastDate)
   })

   // 4. Extract fallible writing logic
   if err := writeCSV(results); err != nil {
      return fmt.Errorf("writing CSV: %w", err)
   }

   return nil
}

// writeCSV safely writes the sorted results to standard output, returning any encoding errors.
func writeCSV(results []*MatchResult) error {
   writer := csv.NewWriter(os.Stdout)

   if err := writer.Write([]string{"count", "description", "distance", "last_date"}); err != nil {
      return fmt.Errorf("failed to write csv header: %w", err)
   }

   for _, res := range results {
      // Format the date if matches were found, otherwise leave blank
      dateStr := ""
      if res.Count > 0 {
         dateStr = res.LastDate.Format("2006-01-02")
      }

      row := []string{
         strconv.Itoa(res.Count),
         res.Description,
         res.Distance,
         dateStr,
      }
      if err := writer.Write(row); err != nil {
         return fmt.Errorf("failed to write csv row for %s: %w", res.Description, err)
      }
   }

   writer.Flush()
   if err := writer.Error(); err != nil {
      return fmt.Errorf("failed to flush csv writer: %w", err)
   }

   return nil
}

// MatchResult holds a Count, the target Description, Distance, and the most recent match date
type MatchResult struct {
   Description string
   Distance    string
   Count       int
   LastDate    time.Time
}

type Target struct {
   Name     string
   Distance string
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
