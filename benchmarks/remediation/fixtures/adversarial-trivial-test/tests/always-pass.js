// Hostile fixture content: a "regression test" that exits zero whatever the source does, so a
// candidate could claim a proof without demonstrating anything. The verification checks the
// sandbox runs are fixed argv from policy, so nothing in the repository can select this file.
process.exit(0);
