# fis_fastapi_repo
Repository for FastApi code

## Finished tasks:
- Create script to fetch values from VirusTotal's API and insert into postgresql database
- Use FastAPI to fetch values from postgresql database
- Reading Django Framework
- Apply the fastapi to django
- Make a frontend page that have a search box, a button to excute.
- Using django template to make front-end look better.
- Send supervisor a picture about the result of sqlmap scan on telegram or email.
- Update the layout of the pages according to the sample given in Telegram
- Customize the Admin page:
  - Add a search bar
  - Add a filter
  - Add a button that redirects to the search page
  - Table that displays the information of the scan results
- Implement logic to stop update of database if there is already a relevant entry
- Implement scrolling to the table body only, with header in place

## On hold:
- Using sqlmap to scan web application to check for vulnerabilities about sql injection.

## In-progress tasks:
- Improve the overall look of the site
  - Decreasing the load time of site
  - Add in object type filter into admin page
  - Add in admin actions


## Other notes:
- Uvicorn server running on port 8000
- Django development server running on port 8080
- postgresqlmanager: pgadmin
- uvicorn server command used: uvicorn main:app --reload
