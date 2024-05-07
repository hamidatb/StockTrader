import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

db.execute("DROP TABLE IF EXISTS transactions")

db.execute("""
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    symbol TEXT NOT NULL,
    shares INTEGER NOT NULL,
    price REAL NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
""")
# These are for performance purposes
db.execute("CREATE INDEX IF NOT EXISTS idx_symbol ON transactions(symbol)")
db.execute("CREATE INDEX IF NOT EXISTS idx_user_id ON transactions(user_id)")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]

    # Get the user's current cash balance
    user_data = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    cash = user_data[0]["cash"]

    # Retrieve the user's stock transactions grouped by stock symbol
    stocks = db.execute("""
        SELECT symbol, SUM(shares) as total_shares
        FROM transactions
        WHERE user_id = ?
        GROUP BY symbol
        HAVING total_shares > 0
    """, user_id)

    # Lookup the current price for each stock and calculate the total value
    holdings = []
    total_portfolio_value = cash  # Start with cash and add each stock's total value

    for stock in stocks:
        stock_info = lookup(stock["symbol"])
        if stock_info:
            total_value = stock_info["price"] * stock["total_shares"]
            holdings.append({
                "symbol": stock["symbol"],
                "shares": stock["total_shares"],
                "price": stock_info["price"],
                "total_value": total_value
            })
            total_portfolio_value += total_value

    # Render an HTML table with the stock data and total values
    return render_template("index.html", holdings=holdings, cash=cash, total_portfolio_value=total_portfolio_value)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Validate the user input in the bavkrnf
        if not symbol:
            return apology("Must provide stock symbol", 400)
        if not shares or not shares.isdigit() or int(shares) <= 0:
            return apology("Shares must be a positive integer", 400)
        stock = lookup(symbol)
        if not stock:
            return apology("Invalid stock symbol", 400)

        # Now that the input must be valid, buy the stock.
        # Check if the user can afford the stock
        user_id = session["user_id"]
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        total_cost = float(stock["price"]) * int(shares)

        # If they can't afford it, tap out
        if float(cash) < total_cost:
            return apology("Cannot afford the number of shares at the current price", 400)

        # If the user can afford the stock, process the purchase
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", total_cost, user_id)
        db.execute("INSERT INTO transactions (user_id, type, symbol, shares, price) VALUES (?, ?, ?, ?, ?)",
                   user_id, 'buy', symbol, int(shares), stock["price"])

        return redirect("/")
    else:
        # If they're navigating to buy through clicking the link or something, return the html page to them
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    user_id = session["user_id"]

    # Retrieve the user's stock transactions grouped by stock symbol
    transactions = db.execute("""
        SELECT *
        FROM transactions
        WHERE user_id = ?
    """, user_id)

    return render_template("history.html", history=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        # Get stock symbol from the form
        symbol = request.form.get("symbol")

        # Ensure that a symbol was submitted
        if not symbol:
            return apology("Must provide stock symbol", 400)

        # Look up the stock price using lookup
        stock = lookup(symbol)

        # Check if the stock lookup was successful
        if not stock:
            return apology("Invalid stock symbol", 400)

        # Render the quoted.html template with stock info
        return render_template("quoted.html", stock=stock)
    else:
        # User reached route via GET (as by navigating to /quote or clicking a link)
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    # Handle POST request for registration
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Validate form input
        if not username:
            return apology("Must provide username", 400)
        if not password or not confirmation:
            return apology("Must provide password and confirm it", 400)
        if password != confirmation:
            return apology("Passwords do not match", 400)

        # Check if username already exists
        user_check = db.execute("SELECT * FROM users WHERE username = ?", username)
        if user_check:
            return apology("Username already exists", 400)

        # Hash the password using werkzeug.security (Always do this, don't just store raw passwords)
        hash = generate_password_hash(password)

        # Insert the new user into the users table
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)

        # I'm going to log user directly after registration
        session["user_id"] = db.execute(
            "SELECT id FROM users WHERE username = ?", username)[0]["id"]

        # Redirect to the home page to show the user their stocks
        return redirect("/")

    # Handle GET request to show the registration form, when they want to see it
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    # If the user is submitting through the form what they want to sell
    if request.method == "POST":
        user_id = session["user_id"]

        symbol = request.form.get("symbol").upper()
        # Check if its a valid symbol
        # Check if the user has enough shares of that symbol to actually sell it
        if not symbol:
            return apology("Must provide stock symbol", 400)

        stock = lookup(symbol)
        if not stock:
            return apology("Invalid stock symbol", 400)

        shares_to_sell = int(request.form.get("shares"))
        if not request.form.get("shares").isdigit() or shares_to_sell <= 0:
            return apology("Shares must be a positive integer", 400)

        # Find out the total amount of shares the user has of that stock
        user_data = db.execute("""
            SELECT SUM(shares) as total_shares
            FROM transactions
            WHERE user_id = ? AND symbol = ?
            GROUP BY symbol
            """, user_id, symbol)
        if not user_data:
            return apology("Not enough shares to sell", 400)

        # Find out the total amount of shares they have of that stock
        user_shares = user_data[0]["total_shares"]
        if user_shares < shares_to_sell:
            return apology("Not enough shares to sell", 400)

        # Sell and update their current cash balance
        # Find out how much cash they make from selling their shares then update that
        total_revenue = float(stock["price"]) * shares_to_sell
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", total_revenue, user_id)
        # Decrease the amount of shares they have
        db.execute("INSERT INTO transactions (user_id, type, symbol, shares, price) VALUES (?, ?, ?, ?, ?)",
                   user_id, 'sell', symbol, -shares_to_sell, stock["price"])

        return redirect("/")
    # If the user is navigating to the sell page from the nav bar or other link.
    else:
        user_id = session["user_id"]
        stocks = db.execute(
            "SELECT symbol, SUM(shares) AS total_shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0", user_id)
        print("Stocks data:", stocks)  # Debug print to check what data is being fetched
        if not stocks:
            print("No stocks available or error fetching stocks.")
        return render_template("sell.html", stocks=stocks)


def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]

    # Get the user's current cash balance
    user_data = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    cash = user_data[0]["cash"]

    # Retrieve the user's stock transactions grouped by stock symbol
    stocks = db.execute("""
        SELECT symbol, SUM(shares) as total_shares
        FROM transactions
        WHERE user_id = ?
        GROUP BY symbol
        HAVING total_shares > 0
    """, user_id)

    # Lookup the current price for each stock and calculate the total value
    holdings = []
    total_portfolio_value = cash  # Start with cash and add each stock's total value

    for stock in stocks:
        stock_info = lookup(stock["symbol"])
        if stock_info:
            total_value = stock_info["price"] * stock["total_shares"]
            holdings.append({
                "symbol": stock["symbol"],
                "shares": stock["total_shares"],
                "price": stock_info["price"],
                "total_value": total_value
            })
            total_portfolio_value += total_value

    # Render an HTML table with the stock data and total values
    return render_template("index.html", holdings=holdings, cash=cash, total_portfolio_value=total_portfolio_value)


# Allowing users to change their password
@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        user_id = session["user_id"]
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        # Check if old password is correct
        user = db.execute("SELECT hash FROM users WHERE id = ?", user_id)
        if not check_password_hash(user[0]["hash"], old_password):
            return apology("Invalid old password", 403)

        # Check if new password and confirmation match
        if new_password != confirmation:
            return apology("New passwords do not match", 400)

        # Update the password hash in the database
        new_hash = generate_password_hash(new_password)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hash, user_id)
        flash("Password changed successfully!")
        return redirect("/")

    else:
        return render_template("change_password.html")
