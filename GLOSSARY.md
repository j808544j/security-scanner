# Mini Gauntlet

Mini Gauntlet evaluates cloud configuration from an inventory snapshot and reports the results of posture checks.

## Language

**Inventory snapshot**  
A point-in-time record of cloud accounts, their resource collections, and collection read errors. Its timestamp is the reference for age-based checks.

**Account**  
A cloud account, subscription, or project represented by one entry in the inventory snapshot.

**Scan**  
One evaluation of the applicable checks across a selected set of accounts. Its status is `RUNNING`, `COMPLETED`, or `FAILED`.

**Check**  
A rule with a stable ID and severity that applies to one resource collection for one cloud provider.

**Finding**  
The result of a check for a resource, or for an unreadable collection when no resource ID is available. Its status is `PASS`, `FAIL`, or `CANNOT_SCAN`.

**Posture score**  
The percentage of evaluated findings that passed, rounded to one decimal place. `CANNOT_SCAN` findings are excluded, and the score is null when there are zero `PASS` and `FAIL` findings.
