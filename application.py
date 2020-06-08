import os
import sys

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    stocks = db.execute("SELECT symbol, SUM(shares) as total_shares FROM history WHERE id = :id GROUP BY symbol",
                        id=session['user_id'])
    pre_available_cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
    available_cash = pre_available_cash[0]["cash"]
    total_shares_value = 0

    for stock in stocks:
        symbol = stock["symbol"]
        lookup_data = lookup(symbol)
        stock["name"] = lookup_data["name"]
        total_shares = stock["total_shares"]
        stock["price"] = usd(lookup_data["price"])
        stock["total"] = usd(total_shares * lookup_data["price"])
        total_shares_value += total_shares * lookup_data["price"]

    grand_total = available_cash + total_shares_value

    if stocks == []:
        return render_template("index.html", available_cash=usd(available_cash), grand_total=usd(grand_total))

    return render_template("index.html", stocks=stocks, symbol=symbol, total_shares=total_shares,
                           available_cash=usd(available_cash), grand_total=usd(grand_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        sql_results_cash = db.execute("SELECT cash FROM users WHERE id=:id", id=session['user_id'])
        first_sql_result = sql_results_cash[0]
        cash = first_sql_result["cash"]

        try:
            int(request.form.get("shares"))
        except ValueError:
            return apology("shares must be a positive integer", 400)

        if not request.form.get("symbol") or lookup(request.form.get("symbol")) == None:
            return apology("must provide valide symbol", 400)

        if not request.form.get("shares") or int(request.form.get("shares")) < 0:
            return apology("must provide positive number of shares", 400)

        else:
            shares = int(request.form.get("shares"))
            symbol_in_api = lookup(request.form.get("symbol"))
            price = float(symbol_in_api["price"])
            updated_cash = cash - shares * price
            symbol = str(symbol_in_api["symbol"])

            if updated_cash < 0:
                return apology("cant afford")

            db.execute("INSERT INTO history (symbol, shares, price, id) VALUES (:symbol, :shares, :price, :id)",
                       symbol=symbol, shares=shares, price=price, id=session['user_id'])

            db.execute("UPDATE users SET cash = :updated_cash WHERE id=:id",
                       updated_cash=updated_cash, id=session['user_id'])

            flash("Buyed!")

            return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    username = request.args.get("username")
    db_request = db.execute("SELECT username FROM users WHERE username=:username", username=username)
    result = True if len(db_request) == 0 else False
    return jsonify(result)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    history = db.execute("SELECT * FROM history WHERE id=:id", id=session['user_id'])
    for stock in history:
        stock["price"] = usd(stock["price"])

    return render_template("history.html", history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

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

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

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
    """Get stock quote."""

    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)

        founded_symbol = lookup(request.form.get("symbol"))

        if founded_symbol == None:
            return apology("must provide valid symbol", 400)

        return render_template("quoted.html", name=founded_symbol["name"], price=usd(founded_symbol["price"]),
                               symbol=founded_symbol["symbol"])

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        if not request.form.get("username"):
            return apology("must provide username", 400)

        elif len(db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))) != 0:
            return apology("username was already taken", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure password confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide confirmation", 400)

        # Ensure password and confirmation are the same
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("password and confirmation must be the same", 400)

        # Hashing the password and addidng user to db
        else:
            hash = generate_password_hash(request.form.get("password"))
            db.execute("INSERT INTO users(username, hash) VALUES(:username, :hash)",
                       username=request.form.get("username"), hash=hash)

        flash("Registered!")

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # open the page
    if request.method == "GET":
        stocks = db.execute("SELECT symbol FROM history WHERE id=:id GROUP BY symbol", id=session['user_id'])
        quotes = {}
        for stock in stocks:
            quotes[stock["symbol"]] = lookup(stock["symbol"])

        return render_template("sell.html", stocks=stocks, quotes=quotes)

    else:
        # ensure symbol is selected
        symbol_from_form = request.form.get("symbol")
        if not symbol_from_form:
            return apology("Invalid Symbol")

        # shares is positive integer
        shares_from_form = int(request.form.get("shares"))
        if shares_from_form < 0:
            return apology("Must be positive integer")

        user_shares = db.execute("SELECT symbol, SUM(shares) as shares FROM history WHERE id=:id AND symbol=:symbol",
                                 id=session['user_id'], symbol=symbol_from_form)

        current_stock = lookup(symbol_from_form)

        if not user_shares[0]["symbol"] or int(user_shares[0]["shares"]) < shares_from_form:
            return apology("You don't hold enough shares to sell that quantity")

        db.execute("INSERT INTO history (symbol, shares, price, id) VALUES (:symbol, :shares, :price, :id)",
                   symbol=symbol_from_form, shares=-shares_from_form,
                   price=int(current_stock["price"]), id=session['user_id'])

        flash("Sold!")
        return redirect("/")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change password"""

    if request.method == "POST":
        old_password = request.form.get("old_password")
        if not old_password:
            return apology("Must provide old password")

        hashed_password_from_db = db.execute("SELECT hash FROM users  WHERE id = :user_id", user_id=session["user_id"])
        old_password_hashed = generate_password_hash(old_password)

        if len(hashed_password_from_db) != 1 or not check_password_hash(hashed_password_from_db[0]["hash"], old_password):
            return apology("invalid password")

        if not request.form.get("new_password"):
            return apology("must provide new password")

        # Ensure new password confirmation is not empty
        elif not request.form.get("new_password_again"):
            return apology("must provide new password confirmation")

        elif request.form.get("new_password") != request.form.get("new_password_again"):
            return apology("new password and confirmation must match")

        old_password_hashed = generate_password_hash(request.form.get("new_password"))

        db.execute("UPDATE users SET hash=:hash WHERE id=:user_id", user_id=session["user_id"], hash=old_password_hashed)

        flash("Password Changed!")
        return redirect("/")

    else:
        return render_template("change_password.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
