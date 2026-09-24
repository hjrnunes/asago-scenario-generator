Feature: HTML visualization of a run directory
  The render-run command reads a completed run output directory and
  produces one self-contained HTML file with curated sections for the
  main artifacts, a collapsible raw viewer for every file, scenario
  filtering, and sidebar navigation. All CSS and JavaScript is inline;
  no external dependencies. Rendering is read-only, offline, and
  lenient about missing artifacts.

  Background:
    Given a synthetic run directory with artifacts

  Scenario: rendering produces one self-contained HTML file
    When the run directory is rendered
    Then the visualization exists at the default output path
    And the HTML contains inline CSS and no external stylesheet

  Scenario: scenario cards expose the executable content
    When the run directory is rendered
    Then the HTML shows scenario "SCN-001" with its execution route

  Scenario: the raw viewer covers every file
    When the run directory is rendered
    Then the raw artifacts section includes "notes.txt"

  Scenario: artifact content is escaped
    When the run directory is rendered
    Then the HTML escapes the injected script payload

  Scenario: missing artifacts render leniently
    Given a run directory with only a manifest
    When the run directory is rendered
    Then the visualization records absent-artifact notes

  Scenario: the CLI renders a run directory
    When the render-run CLI is invoked
    Then the CLI succeeds and writes the visualization
