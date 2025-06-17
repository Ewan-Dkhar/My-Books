Install all dependencies: npm i

To start server: nodemon index.js

Create a .env file.
Store your secrets/credentials in the .env file as follows:
    DATABASE_PASSWORD="YOUR PASSWORD"
    PG_USER="YOUR POSTGRES USENAME"
    PG_HOST="YOUR HOST NAME" //eg: localhost
    PG_DATABASE="YOUR DATABASE NAME"
    PG_PORT="YOUR DATABASE PORT"
    SESSION_SECRET="YOUR SESSION SECRET"
    GOOGLE_CLIENT_ID="YOUR GOOGLE CLIENT ID"
    GOOGLE_CLIENT_SECRET="YOUR GOOGLE CLIENT SECRET"

Database used "PostgresSQL".
