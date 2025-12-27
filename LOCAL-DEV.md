# Prereqs:
- Install Docker
- Copy `cyberspect.env` and `qcluster.env` from AWS repo to project root folder. `docker-compose-dev.yml` relies on these files to add environment variables to the Cyberspect and Django Q Cluster containers.  See the README.md in the AWS repo for details about .env file modifications.
- Copy any tenant specific JSON files from AWS repo to mobsf/static folder

# Typical Workflow
1.  Spin up all of the containers
2. Run the web app and/or execute API commands
3. Debug and make code changes
4. Spin down the containers
5. Spin the containers back up to incorporate changes
## Running the local dev environment

### Run all containers
The first time run `docker compose -f docker-compose-dev.yml up --build`. This will create running containers for:
- PostgreSQL
- MobSF (mobsf)
- Django Q Cluster (qcluster)

**Recommendation**: run this command in it's own terminal window to monitor logging output.
### Shut down the containers except PostgreSQL
There is no reason to spin down PostgreSQL after it is up and running during development. Consequently, as development proceeds, use the following command to bring down only the mobsf and qcluster containers:

`docker compose -f docker-compose-dev.yml rm -s mobsf qcluster --force`

**Recommendation**: run this command in a second terminal session. You'll see logging output in the first terminal session when the containers spin down.
### Bring the containers back up
After saving changes to your code, scripts, data or configuration, use the following command to bring up only the `mobsf` and `qcluster` containers:

`docker compose -f docker-compose-dev.yml up --build mobsf qcluster -d`

**Recommendation**: run this command in the same terminal session where you ran the `docker compose rm` command (see above). You'll see logging output in the first terminal session as the containers spin up.


