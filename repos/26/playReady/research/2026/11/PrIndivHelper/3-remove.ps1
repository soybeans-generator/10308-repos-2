# ---- 1. Remove the packaged app (run as normal user; add -AllUsers with admin if needed) ----
Get-AppxPackage PrIndivHelper | Remove-AppxPackage

# Verify it's gone
Get-AppxPackage PrIndivHelper   # should return nothing
