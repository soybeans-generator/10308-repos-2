// flag.go KEEP THIS LINE
package maya

import (
   "errors"
   "fmt"
   "io"
   "strconv"
   "strings"
)

// Flag describes one command line flag.
type Flag struct {
   Name  string
   Usage string
   Value FlagValue
   Needs []string

   set bool
}

type FlagBool bool

func (b FlagBool) Default() string {
   if b {
      return "true"
   }
   return ""
}

func (FlagBool) Example() string { return "" }

func (b *FlagBool) Parse(value string) error {
   if value == "" {
      *b = true
      return nil
   }
   parsed, err := strconv.ParseBool(value)
   if err != nil {
      return err
   }
   *b = FlagBool(parsed)
   return nil
}

func (FlagBool) Type() string { return "bool" }

type FlagInt int

func (i FlagInt) Default() string {
   if i != 0 {
      return strconv.Itoa(int(i))
   }
   return ""
}

func (FlagInt) Example() string { return "789" }

func (i *FlagInt) Parse(value string) error {
   parsed, err := strconv.Atoi(value)
   if err != nil {
      return err
   }
   *i = FlagInt(parsed)
   return nil
}

func (FlagInt) Type() string { return "int" }

type FlagSet []*Flag

// IsSet reports whether the flag holding value was given on the command line.
func (set FlagSet) IsSet(value FlagValue) bool {
   for _, flag := range set {
      if flag.Value == value {
         return flag.set
      }
   }
   return false
}

// Parse reads flags from args, which are expected as name or name=value.
func (set FlagSet) Parse(args []string) error {
   for _, arg := range args {
      name, value, _ := strings.Cut(arg, "=")
      if name == "" {
         return fmt.Errorf("bad flag syntax: %s", arg)
      }

      var match *Flag
      for _, flag := range set {
         if flag.Name == "" {
            return errors.New("flag name cannot be empty")
         }
         if !strings.HasPrefix(flag.Name, name) {
            continue
         }
         if match != nil {
            return fmt.Errorf("ambiguous flag: %s", name)
         }
         match = flag
      }
      if match == nil {
         return fmt.Errorf("flag provided but not defined: %s", name)
      }

      if err := match.Value.Parse(value); err != nil {
         return fmt.Errorf("invalid value for flag %s: %w", match.Name, err)
      }
      match.set = true
   }
   return nil
}

// Usage writes the flag index and examples to w.
func (set FlagSet) Usage(w io.Writer, name string) error {
   var b strings.Builder

   b.WriteString("index:\n")
   for _, flag := range set {
      if flag.Name == "" {
         return errors.New("flag name cannot be empty")
      }
      fmt.Fprintf(&b, "     %s %s\n", flag.Name, flag.Value.Type())
      if flag.Usage != "" {
         fmt.Fprintf(&b, "          usage: %s\n", flag.Usage)
      }
      if def := flag.Value.Default(); def != "" {
         fmt.Fprintf(&b, "          default: %s\n", def)
      }
   }

   b.WriteString("\nexamples:\n")

   // A flag whose first letter no other flag shares can be abbreviated to
   // that single letter.
   firstLetter := make(map[byte]int, len(set))
   for _, flag := range set {
      firstLetter[flag.Name[0]]++
   }
   abbreviate := func(flag *Flag) string {
      prefix := flag.Name
      if firstLetter[flag.Name[0]] == 1 {
         prefix = flag.Name[:1]
      }
      if example := flag.Value.Example(); example != "" {
         return prefix + "=" + example
      }
      return prefix
   }

   for _, flag := range set {
      if len(flag.Needs) == 0 {
         fmt.Fprintf(&b, "     %s %s\n", name, abbreviate(flag))
         // After a standalone example, print one line for each flag
         // that lists it in Needs.
         for _, dependent := range set {
            for _, need := range dependent.Needs {
               if need == flag.Name {
                  fmt.Fprintf(&b, "     %s %s %s\n", name, abbreviate(flag), abbreviate(dependent))
                  break
               }
            }
         }
         continue
      }
      for _, need := range flag.Needs {
         needed := set.lookup(need)
         if needed == nil {
            return fmt.Errorf("flag %q needs undefined flag %q", flag.Name, need)
         }
         // A standalone needed flag already printed this example below
         // its own standalone example.
         if len(needed.Needs) > 0 {
            fmt.Fprintf(&b, "     %s %s %s\n", name, abbreviate(needed), abbreviate(flag))
         }
      }
   }

   _, err := io.WriteString(w, b.String())
   return err
}

func (set FlagSet) lookup(name string) *Flag {
   for _, flag := range set {
      if flag.Name == name {
         return flag
      }
   }
   return nil
}

type FlagString string

func (s FlagString) Default() string { return string(s) }

func (FlagString) Example() string { return "xyz" }

func (s *FlagString) Parse(value string) error {
   *s = FlagString(value)
   return nil
}

func (FlagString) Type() string { return "string" }

// FlagValue is the value a Flag holds.
type FlagValue interface {
   Parse(string) error
   Type() string
   Default() string
   Example() string
}

// flag.go KEEP THIS LINE
