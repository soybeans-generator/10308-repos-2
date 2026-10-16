// main.go marker preserve

package main

import (
   "cmp"
   "encoding/csv"
   "flag"
   "fmt"
   "os"
   "slices"
   "strconv"
   "time"
)

var targets = []Target{
   {Name: "CAFE CREAMSTO"},
   {Name: "CHICK-FIL-A"},
   {Name: "DAVES HOT CHICKEN"},
   {Name: "FIREHOUSE SUBS", Distance: "4.2 mi"},
   {Name: "IN-N-OUT", Distance: "4.1 mi"},
   {Name: "JASON'S DELI"},
   {Name: "LA MADELEINE"},
   {Name: "MCDONALD'S"},
   {Name: "SCHLOTZSKYS"},
   {Name: "SHAKE SHACK"},
   {Name: "SHAWARMA PRESS", Distance: "4.5 mi"},
   {Name: "SPRING CREEK"},
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

// main.go marker preserve
