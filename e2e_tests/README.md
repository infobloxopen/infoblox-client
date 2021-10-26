# End-to-end tests

This set of tests is intended for functionality validation on an existing WAPI
instance.

## How to run E2E tests

First, you should export parameters of accessible and running `WAPI` instance.
Then you can use `unittest` module or any other test runner to run the tests
in the `e2e_tests` directory.

```bash
export WAPI_HOST=<WAPI HOST IP> WAPI_USER=<WAPI USERNAME> WAPI_PASS=<WAPI PASSWORD>
python3 -m unittest e2e_tests.test_objects
```

## Warning

Please don't run those tests on the production WAPI instance.
