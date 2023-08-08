import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
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

    if request.method == "POST":
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        # Get all the info needed from database, this can be done with a single query
        holdings = db.execute(
            "SELECT name, symbol, amount FROM holdings WHERE user_id = ? GROUP BY symbol",
            session["user_id"],
        )

        # Get everything ready
        TOTAL = 0
        for stock in holdings:
            # stock["name"] = stock["symbol"]
            price = lookup(stock["symbol"])["price"]
            price_usd = usd(lookup(stock["symbol"])["price"])
            stock["price"] = price_usd
            stock["TOTAL"] = float(format((stock["amount"] * price), ".2f"))
            TOTAL += stock["TOTAL"]  # Add to TOTAL, we need this to still be a float
            stock["TOTAL"] = usd(stock["TOTAL"])  # Now, convert to "usd format"

        # # Testing contents of dict
        # for stock in holdings:
        #     for key in stock:
        #         print(key, stock[key])

        # Get user's balance, format as usd
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]
        grand_total = usd(cash["cash"] + TOTAL)
        cash = usd(cash["cash"])

        return render_template(
            "index.html", holdings=holdings, cash=cash, grand_total=grand_total
        )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Get stock symbol from user
        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)

        # Get shares amount from user
        if not request.form.get("shares"):
            return apology("must provide amount of shares to buy", 400)
        # if (int(request.form.get("shares")) < 1) or not (float(request.form.get("shares")).is_integer()):
        try:
            shares = float(request.form.get("shares"))
        except ValueError:
            return apology("Must provide a valid amount of shares to buy", 400)
        if not shares.is_integer() or shares < 1:
            return apology("Must provide a valid amount of shares to buy", 400)

        # get info of symbol on stock_quote
        stock_quote = lookup(request.form.get("symbol"))
        # if stock_quote == None:
        if not stock_quote:
            return apology("Symbol doesn't exist", 400)

        # Prepare variables for easier handling
        amount = shares
        name = stock_quote["name"]
        symbol = stock_quote["symbol"]
        price = stock_quote["price"]
        total = float(format((price * int(amount)), ".2f"))
        # print("Stock to buy: {}. Ammount to buy: {}. Current price: {}. Total: {}"
        #       .format(name, amount, price, total))

        # check for user's balance, return apology if total to buy is larger than user's balance
        user_row = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]

        if total > user_row["cash"]:
            return apology("Can't afford", 400)

        # Insert to transactions table
        db.execute(
            "INSERT INTO transactions(user_id, type, symbol, amount, price) VALUES(?, ?, ?, ?, ?)",
            session["user_id"],
            "buy",
            symbol,
            amount,
            price,
        )
        # Update holdings table
        existing_row = db.execute("SELECT * FROM holdings WHERE symbol = ?", symbol)
        if existing_row:
            new_amount = existing_row[0]["amount"] + int(amount)
            db.execute(
                "UPDATE holdings SET amount = ? WHERE symbol = ?", new_amount, symbol
            )
        else:
            db.execute(
                "INSERT INTO holdings(user_id, name, symbol, amount) VALUES(?, ?, ?, ?)",
                session["user_id"],
                name,
                symbol,
                amount,
            )

        # Update users table (cash is not the same because the user spent money)
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?",
            user_row["cash"] - total,
            session["user_id"],
        )

        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        return redirect("history.html")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        # Get all the info needed from database, this can be done with a single query
        transactions = db.execute(
            "SELECT * FROM transactions WHERE user_id = ?;", session["user_id"]
        )

        # Prepare dictionary to display info
        # for stock in holdings:
        #     stock["name"] = stock["symbol"]
        #     price = lookup(stock["symbol"])["price"]
        #     price_usd = usd(lookup(stock["symbol"])["price"])
        #     stock["price"] = price_usd
        #     stock["TOTAL"] = float(format((stock["amount"] * price), ".2f"))
        #     TOTAL += stock["TOTAL"] # Add to TOTAL, we need this to still be a float
        #     stock["TOTAL"] = usd(stock["TOTAL"]) # Now, convert to "usd format"
        for transaction in transactions:
            transaction["price"] = usd(transaction["price"])
            print(transaction)

        # # Testing contents of dict
        # for stock in holdings:
        #     for key in stock:
        #         print(key, stock[key])

        return render_template("history.html", transactions=transactions)


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


@app.route("/change_pass", methods=["GET", "POST"])
def change_pass():
    """Change user password"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for user
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Ensure new password was subitted
        elif not request.form.get("password_new"):
            return apology("must provide new password", 403)
        # Ensure password confirmation was subitted
        elif not request.form.get("password_confirm"):
            return apology("must provide confirmation", 403)

        # Check if new passowrd and confirmation match
        if request.form.get("password_new") != request.form.get("password_confirm"):
            return apology("New Password and confirmation don't match!")

        # Generate hash and update table
        pass_hash = generate_password_hash(
            request.form.get("password_new"), method="pbkdf2", salt_length=16
        )
        # new_user = db.execute("INSERT INTO users(username, hash) VALUES(?, ?)", request.form.get("username"), pass_hash)
        db.execute(
            "UPDATE users SET hash = ? WHERE id = ?", pass_hash, session["user_id"]
        )

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("change_pass.html")


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
    """Get stock quote."""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Get stock symbol from user
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)

        print("Symbol: {}".format(request.form.get("symbol")))

        stock_quote = lookup(request.form.get("symbol"))
        if stock_quote == None:
            return apology("Symbol doesn't exist")

        # for key in stock_quote:
        #     print(key, stock_quote[key])

        return render_template(
            "quoted.html",
            name=stock_quote["name"],
            symbol=stock_quote["symbol"],
            price=usd(stock_quote["price"]),
        )

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure password confirmation was subitted
        elif not request.form.get("confirmation"):
            return apology("must provide confirmation", 400)

        # Check if passowrd and confirmation match
        if request.form.get("confirmation") != request.form.get("password"):
            return apology("Password and confirmation don't match!")

        # Check if username doesn't exist already
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )
        if user:
            return apology("Username already exists!", 400)

        pass_hash = generate_password_hash(
            request.form.get("password"), method="pbkdf2", salt_length=16
        )

        # Insert new user into database
        new_user = db.execute(
            "INSERT INTO users(username, hash) VALUES(?, ?)",
            request.form.get("username"),
            pass_hash,
        )
        # print("User registered succesfully! Returning to home screen")

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Get symbol and shares from user
        if not request.form.get("symbol"):
            return apology("missing symbol", 403)

        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        value = float(format(shares * (lookup(symbol)["price"]), ".2f"))
        # print("Symbol: {}. Price: {}. Shares to sell: {}. Value: {}".format(symbol, lookup(symbol)["price"], shares, value))

        # Get user's holdings and check if amount to sell is less or equal to user's holdings
        holdings = db.execute(
            "SELECT amount FROM holdings WHERE user_id = ? AND symbol = ?",
            session["user_id"],
            symbol,
        )[0]["amount"]
        user_cash = float(
            format(
                db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[
                    0
                ]["cash"],
                ".2f",
            )
        )
        print(
            "Symbol: {}. Price: {}. Shares to sell: {}. Value: {}. User's cash: {}.".format(
                symbol, lookup(symbol)["price"], shares, value, user_cash
            )
        )

        # Can't sell
        if shares > holdings:
            return apology("too many shares")

        # Can sell, must straight up delete the entire row from holdings; must update users and add transaction
        if shares == holdings:
            db.execute(
                "DELETE FROM holdings WHERE user_id = ? AND SYMBOL = ?",
                session["user_id"],
                symbol,
            )
            db.execute(
                "UPDATE users SET cash = ? WHERE id = ?",
                (user_cash + value),
                session["user_id"],
            )
            db.execute(
                "INSERT INTO transactions(user_id, type, symbol, amount, price) VALUES(?, ?, ?, ?, ?)",
                session["user_id"],
                "sell",
                symbol,
                -shares,
                lookup(symbol)["price"],
            )
            return redirect("/")
        # Can sell, must update holdings, update users and add transaction
        else:
            db.execute(
                "UPDATE holdings SET amount = ? WHERE user_id = ? AND symbol = ?",
                (holdings - shares),
                session["user_id"],
                symbol,
            )
            db.execute(
                "UPDATE users SET cash = ? WHERE id = ?",
                (user_cash + value),
                session["user_id"],
            )
            db.execute(
                "INSERT INTO transactions(user_id, type, symbol, amount, price) VALUES(?, ?, ?, ?, ?)",
                session["user_id"],
                "sell",
                symbol,
                -shares,
                lookup(symbol)["price"],
            )
            return redirect("/")

        return render_template("sell.html")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        # Get stock symbol from user using a select menu, so we first need to fetch user's holdings
        holdings = db.execute(
            "SELECT * FROM holdings WHERE user_id = ?", session["user_id"]
        )

        symbols = []
        for row in holdings:
            symbols.append({row["symbol"]: int(row["amount"])})

        for symbol in symbols:
            print(symbol)

        return render_template("sell.html", symbols=symbols)
