import express from 'express';
import bodyParser from 'body-parser';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import 'dotenv/config'

const app = express();
const port = 3000;
const db = new pg.Client({
    user: "postgres",
    password: process.env.DATABASE_PASSWORD,
    host: 'localhost',
    database: 'mybooks',
    port: 5432
});

db.connect();

let currentUserId;
let isMatch = false;

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

async function hashPassword(password) {
  const saltRounds = 10; // Recommended value, adjust as needed
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  return hashedPassword;
}

async function verifyPassword(password, hashedPassword) {
  const isMatch = await bcrypt.compare(password, hashedPassword);
  return isMatch;
}

// GET
app.get("/", (req, res) => {
    res.redirect("/login");
});

app.get("/login", (req, res) => {
    res.render("login.ejs");
});

app.get("/signup", (req, res) => {
    res.render("signup.ejs");
});

app.get("/new/:username", async (req, res) => {
    const username = req.params.username;
    if(isMatch){
        try {
            const result = await db.query("SELECT * FROM users WHERE username = $1", [username]);
            res.render("new.ejs", {userId: result.rows[0].id, username})
        } catch (error) {
            console.log("Error:", error)
            res.send(500).json({ error: 'Server error' })
        }
    } else{
        res.redirect("/login");
    }
});

app.get("/books/:username/:bookId", async (req, res) => {
    const username = req.params.username;
    const bookId = req.params.bookId;

    try {
        if(isMatch){
            const result =  await db.query("SELECT * FROM books WHERE id = $1", [bookId]);
            res.render("book.ejs", {book: result.rows[0], username: username})
        } else{
            res.redirect("/login");
        }
    } catch (error) {
        console.error('Error during Searching:', error);
        res.status(404).json({ error: 'Book not found' });
    }
});

app.get("/edit/:username/:bookId", async (req, res) => {
    const username = req.params.username;
    const bookId = req.params.bookId;

    try {
        if(isMatch){
            const result =  await db.query("SELECT * FROM books WHERE id = $1", [bookId]);
            res.render("new.ejs", {book: result.rows[0], username: username, bookId: bookId, edit: true})
        } else{
            res.redirect("/login");
        }
    } catch (error) {
        console.error('Error during Searching:', error);
        res.status(404).json({ error: 'Book not found' });
    }
});

app.get("/home/:username", async (req, res) => {
    const username = req.params.username;

    if(isMatch){
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
});

// POST
app.post("/auth", async (req, res) => {
    const {username, password} = req.body;
    
    try {
        const result = await db.query("SELECT * FROM users WHERE username = $1", [username]);

        if(result.rows.length === 0){
            return res.render('notFound.ejs');
        }

        const storedHashedPassword = result.rows[0].password;
        isMatch = await verifyPassword(password, storedHashedPassword);

        if (isMatch) {
            // User authenticated successfully
            currentUserId = result.rows[0].id;
            res.redirect(`/home/${username}`);
        } else {
            // Password incorrect
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Login failed' });
    }
})

app.post("/register", async (req, res) => {
    const {name, username, password} = req.body;
    const hashedPassword = await hashPassword(password);

    try {
        const result = await db.query("INSERT INTO users (name, username, password) VALUES ($1, $2, $3) RETURNING id", [name, username, hashedPassword])
        currentUserId = result.rows[0].id;
        isMatch = true;
        res.redirect(`/home/${username}`);
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
})

app.post("/add/:username", async (req, res) => {
    const username = req.params.username;
    const { userId, title, author, isbn, rating, summary, notes, review } = req.body;
    
    if(isMatch){
        try {
            await db.query("INSERT INTO books (title, author, user_id, notes, summary, rating, review, isbn) VALUES ($1, $2, $3, $4, $5, $6, $7 ,$8)", [title, author, userId, notes, summary, rating, review, isbn]);
            res.redirect(`/home/${username}`)
        } catch (error) {
            console.error('Error during creation:', error);
            res.status(500).json({ error: 'Creation failed' });
        }
    } else {
        res.redirect('/login');
    }
})

app.post("/edit/:username", async (req, res) => {
    const username = req.params.username;

    const { userId, bookId, title, author, isbn, rating, summary, notes, review } = req.body;
    
    if(isMatch){
        try {
            await db.query("UPDATE books SET title = $1, author = $2, user_id = $3, notes = $4, summary = $5, rating = $6, review = $7, isbn = $8 WHERE id = $9", [title, author, userId, notes, summary, rating, review, isbn, bookId]);
            res.redirect(`/home/${username}`)
        } catch (error) {
            console.error('Error during edit:', error);
            res.status(500).json({ error: 'Edit failed' });
        }
    } else {
        res.redirect('/login');
    }
})

app.listen(port, () => {
    console.log(`Your server is running on http://localhost:${port}`);
});