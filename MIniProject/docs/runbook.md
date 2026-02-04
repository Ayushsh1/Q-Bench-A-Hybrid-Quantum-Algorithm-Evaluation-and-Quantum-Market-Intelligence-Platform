# Runbook

## Start API
- python -m qbench.api.app

## Start GUI
- python -m qbench.gui.app

## Notes
- Start API first, then GUI.
- GUI falls back to cached datasets if API is unavailable.
- Benchmark tab requires API and generates plot + CSV in the plots folder.
- Use “Save Plot As...” to export a PNG to a custom location.
- Use “Save CSV As...” to export benchmark metrics to CSV.
