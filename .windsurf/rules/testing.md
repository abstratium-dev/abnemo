---
trigger: glob
globs: tests/**/*.py
---

ALWAYS disable conda with `conda deactivate`. 
- Run tests using `python3 -m pytest`
- Don't use things like "head -n 10" very vigourously since you end up having to rerun the tests again in order to find errors. It is inefficient and slows us down.

**When you execute the tests, send the output to a file in the `/tmp` directory. search that file for results. use the same file for all test runs. That way, you will not run tests, and then need to run them again, in order to search for specific results!**

You must check that coverage is at 80% statement coverage and 70% branch coverage. Use coverage results to find missing tests.

Do not write senseless tests just to increase the coverage.

Make sure that all tests contain assertions and not just for rudimentary things. The tests should be meaningful, useful and they must test functionality.

It is EXTREMELY IMPORTANT that this project be tested using unit and integration tests.

ALWAYS ensure that ALL tests run, regardless of whether they are relevant to the current context.
NEVER disable tests. NEVER use `@pytest.mark.skip`
NEVER delete tests just because you cannot make them work.
Do ask for help if you are going in circles and not getting the tests to pass.
ALWAYS keep testing until all the tests run.