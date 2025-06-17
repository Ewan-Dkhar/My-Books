import express from 'express';
import bodyParser from 'body-parser';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import 'dotenv/config'
import session from 'express-session';
import passport from 'passport';
import { Strategy } from 'passport-local';
import GoogleStrategy from 'passport-google-oauth2';

const app = express();
const port = 3000;

// Connecting to database
const db = new pg.Client({
    user: process.env.PG_USER,
    password: process.env.DATABASE_PASSWORD,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    port: process.env.PG_PORT
});

db.connect();

// Global variables
let currentUserId;
let currentUsername;

// Middleware
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24,
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// A function that creates a hash of a password using bcrypt
async function hashPassword(password) {
  const saltRounds = 10; // Recommended value, adjust as needed
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  return hashedPassword;
}

// A function that compares the password with the hashed paassword and returns a boolean
async function verifyPassword(password, hashedPassword) {
  const isMatch = await bcrypt.compare(password, hashedPassword);
  return isMatch;
}

// GET
app.get("/", (req, res) => {
    res.redirect("/login");
});

// login route
app.get("/login", (req, res) => {
    res.render("login.ejs");
});

// sign up route
app.get("/signup", (req, res) => {
    res.render("signup.ejs");
});

// new post page route
app.get("/new/:username", async (req, res) => {
    const username = req.params.username;
    if(req.isAuthenticated()){
        try {
            const result = await db.query("SELECT * FROM users WHERE username = $1", [username]);
            res.render("new.ejs", {userId: result.rows[0].id, username})
        } catch (error) {
            console.log("Error:", error)
            res.render('error.ejs', { status: 500, error: 'Server error' });
        }
    } else{
        res.redirect("/login");
    }
});

// book details route
app.get("/books/:username/:bookId", async (req, res) => {
    const username = req.params.username;
    const bookId = req.params.bookId;

    try {
        if(req.isAuthenticated()){
            const result =  await db.query("SELECT * FROM books WHERE id = $1", [bookId]);
            res.render("book.ejs", {book: result.rows[0], username: username})
        } else{
            res.redirect("/login");
        }
    } catch (error) {
        console.error('Error during Searching:', error);
        res.render('error.ejs', { status: 404, error: 'Book not found' });
    }
});

// editpage route
app.get("/edit/:username/:bookId", async (req, res) => {
    const username = req.params.username;
    const bookId = req.params.bookId;

    try {
        if(req.isAuthenticated()){
            const result =  await db.query("SELECT * FROM books WHERE id = $1", [bookId]);
            res.render("new.ejs", {book: result.rows[0], username: username, bookId: bookId, edit: true})
        } else{
            res.redirect("/login");
        }
    } catch (error) {
        console.error('Error during Searching:', error);
        res.render('error.ejs', { status: 404, error: 'Book not found' });
    }
});

// homepage route
app.get("/home/:username", async (req, res) => {
    if(req.isAuthenticated()){
        const username = req.params.username;
        if(username === currentUsername){
            try {
                const result =  await db.query("SELECT books.id, books.title, books.author, books.notes, books.summary, books.rating, books.review, books.isbn, users.name, users.id AS uid, users.username FROM books JOIN users ON users.id = books.user_id WHERE username = $1", [username]);
                
                res.render("index.ejs", {books: result.rows, name: result.rows[0].name, username: result.rows[0].username})
            } catch (error) {
                const result =  await db.query("SELECT * FROM users WHERE username = $1", [username]);
                res.render("index.ejs", {username: result.rows[0].username})
            }
        } else{
            res.redirect("/login");
        }
    } else {
        res.redirect('/login')
    }
});

// Authentication using google
app.get("/auth/google", passport.authenticate("google", {
  scope: ["profile", "email"],
}));

app.get("/auth/google/mybooks", (req, res, next) => {
    passport.authenticate("google", (err, user, info) => {
        if (err) return next(err);
        if (!user) return res.redirect("/login");

        req.logIn(user, (err) => {
        if (err) return next(err);
            // Now user is authenticated, you can access user.username
            return res.redirect(`/home/${user.username}`);
        });
    })(req, res, next);
});

// logout
app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/delete/:username/:bookId", async (req, res) => {
    if(req.isAuthenticated()){
        const bookId = req.params.bookId;
        const username = req.params.username;
        try {
            await db.query("DELETE FROM books WHERE id = $1", [bookId]);
            res.redirect(`/home/${username}`);
        } catch (error) {
            console.error("Error during login:", err);
            return res.status(500).render("error.ejs", {
                status: 500,
                error: "Failed to Delete."
            });
        }
    }
})

// POST

// Authetication using local Strategy
app.post("/auth", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if(err === '404'){
        return res.status(404).render("notFound.ejs", {
            username: req.body.username
        });
    }
    else if(err === '403'){
        return res.status(403).render("login.ejs", {
            error: 'Invalid credentials. Please enter correct password.'
        });
    }
    else if (err){
        console.error("Error during login:", err);
        return res.status(500).render("error.ejs", {
            status: 500,
            error: "Login failed. Please try again later."
        });
    }
    if (!user) return res.redirect("/login");

    req.logIn(user, (err) => {
      if (err) return next(err);
      // Now user is authenticated, you can access user.username
      return res.redirect(`/home/${user.username}`);
    });
  })(req, res, next);
});

// Registering a user
app.post("/register", async (req, res) => {
    const {name, username, password} = req.body;
    const hashedPassword = await hashPassword(password);

    try {
        const result = await db.query("INSERT INTO users (name, username, password) VALUES ($1, $2, $3) RETURNING *", [name, username, hashedPassword])
        const user = result.rows[0];
        currentUserId = result.rows[0].id;
        currentUsername = username;
        req.login(user, (err) => {
            console.log(err);
            res.redirect(`/home/${username}`);
        })
    } catch (error) {
        console.error('Error during registration:', error);
        res.render('error.ejs', { status: 403 ,error: 'Registration failed! Username already in use.' });
    }
})

// Adding a new post
app.post("/add/:username", async (req, res) => {
    const username = req.params.username;
    const { userId, title, author, isbn, rating, summary, notes, review } = req.body;
    
    if(req.isAuthenticated()){
        try {
            await db.query("INSERT INTO books (title, author, user_id, notes, summary, rating, review, isbn) VALUES ($1, $2, $3, $4, $5, $6, $7 ,$8)", [title, author, userId, notes, summary, rating, review, isbn]);
            res.redirect(`/home/${username}`)
        } catch (error) {
            console.error('Error during creation:', error);
            res.render('error.ejs', { status: 500 ,error: "Couldn't create new post." });
        }
    } else {
        res.redirect('/login');
    }
})

// editing a post
app.post("/edit/:username", async (req, res) => {
    const username = req.params.username;

    const { userId, bookId, title, author, isbn, rating, summary, notes, review } = req.body;
    
    if(req.isAuthenticated()){
        try {
            await db.query("UPDATE books SET title = $1, author = $2, user_id = $3, notes = $4, summary = $5, rating = $6, review = $7, isbn = $8 WHERE id = $9", [title, author, userId, notes, summary, rating, review, isbn, bookId]);
            res.redirect(`/home/${username}`)
        } catch (error) {
            console.error('Error during edit:', error);
            res.render('error.ejs', { status: 500 ,error: "Couldn't edit post." });
        }
    } else {
        res.redirect('/login');
    }
})

// local strategy(authentication)
passport.use("local", new Strategy(async function verify(username, password, cb){
    try {
        const result = await db.query("SELECT * FROM users WHERE username = $1", [username]);

        if(result.rows.length === 0){
            return cb('404');
        }

        const storedHashedPassword = result.rows[0].password;
        const isMatch = await verifyPassword(password, storedHashedPassword);

        if (isMatch) {
            // User authenticated successfully
            const user = result.rows[0];
            currentUserId = result.rows[0].id;
            currentUsername = username;
            return cb(null, user);
        } else {
            // Password incorrect
            return cb('403', false);
        }
    } catch (error) {
        console.error('Error during login:', error);
        return cb(error);
    }
}));

// google strategy(oauth)
passport.use("google", new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/mybooks",
    userProfileURL: "https://www.googleapis.com/oauth/v3/userinfo",
}, async (accessToken, refreshToken, profile, cb) => {
    const newUsername = profile.email.slice(0, profile.email.indexOf("@"));

    try {
        const result = await db.query("SELECT * FROM users WHERE username = $1", [newUsername])
        if(result.rows.length === 0){
            const newUser = await db.query("INSERT INTO users(name, username, password) VALUES ($1, $2, $3)", [profile.displayName, newUsername, "google"]);
            currentUsername = newUser.rows[0].username;
            cb(null, newUser.rows[0]);
        } else {
            currentUsername = result.rows[0].username;
            cb(null, result.rows[0]);
        }
    } catch (error) {
        cb(error);
    }
}))

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
    console.log(`Your server is running on http://localhost:${port}`);
});