---
trigger: glob
globs: e2e-tests/**/*.ts
---

- end to end (e2e) tests are written using playwright
- use the playwright-cli skill (.windsurf/skills/playwright-cli/SKILL.md) to help understand what is displayed in the browser and how to use it
- When writing playwright tests for end to end testing, in the `e2e-tests` folder, avoid `page.waitForTimeout`since the docs say "Note that page.waitForTimeout() should only be used for debugging. Tests using the timer in production are going to be flaky. Use signals such as network events, selectors becoming visible and others instead." Note that when using "waitUntil", the docs say "Default is 'load'; 'networkidle' is discouraged for testing."
- tests use the "page object model" pattern - each page is encapsulated in a file in the folder named `e2e-tests/pages`.
- page files should consist of low level functions used to select elements, and higher level functions that encapsulate functionality of the page, e.g. filling in a form or clicking a button. the higher level functions should use the low level functions.
- tests are found in files in the folder `e2e-tests/tests`.
- also use the source code of the web server in the folder `src` to work out how to encapsulate the pages
- tests should include assertions to ensure that the page is displaying the correct information.
- The tests should be meaningful, useful and they must test functionality.
- you don't need to start the server, it will be running already
- if you are writing a test and the description that the user has provide is causing errors, you might have to fix the source code. if you are not sure, ask for help.
- never set the URL directly with the `page.goto` function; use buttons and links to navigate through the application. This is NOT true for starting the test which requires you to use the `goto` function to get to the home page (root path).
- when you run the tests (e.g. `npx playwright test happy.spec.ts`) run them so that playwright doesn't serve an html report at the end, because that blocks you from continuing until i kill the process. this is done by adding `PLAYWRIGHT_HTML_OPEN=never ` before `npx playwright test`. 
- run the tests with just chromium, rather than running the tests in firefox or other browsers too.
- add `data-testid` attributes to the html source if that makes the selection of elements easier or more deterministic
- when you write page object models and tests, make sure that you add logging, so that you can debug the tests when they are failing
