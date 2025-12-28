# Project Goal

The goal of this project is to automate monitoring and downloading of APK files from sidequest whenenver a new version is released. This will provide an archive of APKs for various applications, ensuring that users have access to previous versions if needed.

## Test Data

In the `test_data` folder, you will find sample json responses from the Sidequest API. These files can be used to test the functionality of the agents without making actual API calls.

## Sidequest API

The Sidequest API provides endpoints to retrieve information about applications available on Sidequest. The relevant endpoint for this project is:

https://api.sidequestvr.com/v2/apps/{app_id}

Where `app_id` is the unique identifier for the application.

## App IDs to monitor

The following app IDs are to be monitored for new APK releases:
 
- example1 (pico): 123
- example2 (oculus): 321

## Requests User Agent

See this curl command for headers to use when making requests to the Sidequest API:

```bash
curl 'https://api.sidequestvr.com/v2/apps/EXAMPLE_ID?' \
  -H 'accept: application/json' \
  -H 'accept-language: en-US,en;q=0.9' \
  -H 'content-type: application/json' \
  -H 'if-none-match: W/"c16-c8YoyiW+l73rqXabzkmmFA0SgPg"' \
  -H 'origin: https://sidequestvr.com' \
  -H 'priority: u=1, i' \
  -H 'referer: https://sidequestvr.com/' \
  -H 'sec-ch-ua: "Microsoft Edge";v="143", "Chromium";v="143", "Not A(Brand";v="24"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "Windows"' \
  -H 'sec-fetch-dest: empty' \
  -H 'sec-fetch-mode: cors' \
  -H 'sec-fetch-site: same-site' \
  -H 'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0' \
  -H 'x-sq-sid: c00c88e9-e205-4d9b-9b25-0fea51c640f2' \
  -H 'x-sq-tid: 2f2b26cd-34c1-4cf5-ad16-efaf1b613e6d'
```