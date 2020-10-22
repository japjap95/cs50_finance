import os

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
    #GET ALL PORTFOLIO INFORMATION
    get_id = session["user_id"]
    user_info = db.execute(f"SELECT * FROM users WHERE id = {get_id}")
    name = user_info[0]["username"]
    cash = round(user_info[0]["cash"], 2)

    symbols = db.execute(f"SELECT ticker FROM stocks")
    symbols_array = []
    for i in range (0, len(symbols)):
        symbols_array.append(symbols[i]["ticker"])

    user_holdings = {}
    stock_prices = {}
    stock_names = {}
    total_holding_value = {}
    total_stock_value = 0

    for symbol in symbols_array:
        info = db.execute(f"SELECT holding FROM {symbol} WHERE customer_id = {get_id}")
        if not info:
            continue
        elif info[0]["holding"] == 0:
            continue
        else:
            user_holdings[symbol] = info[0]["holding"]
            stock_prices[symbol] = round(lookup(symbol)["price"], 2)
            stock_names[symbol] = lookup(symbol)["name"]
            total_stock_value += stock_prices[symbol] * int(user_holdings[symbol])

    if not user_holdings:
        return render_template("empty.html", cash = usd(cash), name = name)


    #converting dictionary values into formatted string
    for stock in stock_names:
        total_holding_value[stock] = usd(user_holdings[stock] * stock_prices[stock])
        stock_prices[stock] = usd(stock_prices[stock])


    total_portfolio_value = cash + total_stock_value


    return render_template("index.html", name = name, user_holdings = user_holdings, stock_prices = stock_prices, stock_names = stock_names, cash = usd(cash), total_stock_value = usd(total_stock_value), total_holding_value = total_holding_value, total_portfolio_value = usd(total_portfolio_value))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        symbol = request.form.get("symbol")
        share_info = lookup(symbol)
        if not share_info:
            return apology("The ticker you searched doesn't exist.")
        share_price = float(share_info["price"])
        share_quantity = int(request.form.get("shares"))
        get_id = session["user_id"]
        user_info = db.execute(f"SELECT * FROM users WHERE id = {get_id}")
        customer_id = user_info[0]["id"]
        user_cash = float(user_info[0]["cash"])
        if (share_quantity * share_price) > user_cash:
            return apology("Not enough capital to make purchase")
        else:
            new_user_cash = user_cash - share_quantity * share_price
            db.execute('CREATE TABLE if not exists "trades"(trade_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, customer_id INTEGER NOT NULL, action TEXT NOT NULL, stock TEXT NOT NULL, quantity NUMERIC NOT NULL, price NUMERIC NOT NULL, total_value NUMERIC NOT NULL, datetime TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)')
            db.execute("INSERT INTO trades (customer_id, action, stock, quantity, price, total_value) VALUES (:customer_id, :action, :stock, :quantity, :price, :total_value)", customer_id = customer_id, action = "BUY", stock = symbol, quantity = share_quantity, price = share_price, total_value = share_price * share_quantity)
            db.execute(f"CREATE TABLE if not exists '{symbol}' (customer_id INTEGER PRIMARY KEY NOT NULL, holding NUMERIC NOT NULL)")
            current_holding = db.execute(f"SELECT holding FROM {symbol} WHERE customer_id = {get_id}")
            if not current_holding:
                db.execute(f"INSERT INTO {symbol} (customer_id, holding) VALUES (:customer_id, :holding)", customer_id = customer_id, holding = share_quantity)
                db.execute(f"INSERT INTO stocks (ticker) VALUES (:ticker)", ticker = symbol)
            else:
                new_holding = current_holding[0]["holding"] + share_quantity
                db.execute(f"UPDATE {symbol} SET holding = {new_holding} WHERE customer_id = {get_id}")

            db.execute(f"UPDATE users SET cash = {new_user_cash} WHERE id = {get_id}")
            return render_template("bought.html", share_quantity=share_quantity, stock=symbol, total_price=usd((share_quantity*share_price)))


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    get_id = session["user_id"]
    trading_info = db.execute(f"SELECT * FROM trades WHERE customer_id = {get_id}")

    tickers = {}
    shares = {}
    prices = {}
    totals = {}
    datetime = {}
    actions = {}

    for trades in trading_info:
        tickers[trades["trade_id"]] = trades["stock"]
        shares[trades["trade_id"]] = trades["quantity"]
        prices[trades["trade_id"]] = usd(trades["price"])
        totals[trades["trade_id"]] = usd(trades["total_value"])
        datetime[trades["trade_id"]] = trades["datetime"]
        actions[trades["trade_id"]] = trades["action"]

    return render_template("history.html", datetime = datetime, tickers = tickers, shares = shares, prices = prices, totals = totals, actions = actions)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
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
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    else:
        symbol = request.form.get("symbol")
        share_info = lookup(symbol)
        if share_info is None:
            return apology("Please enter valid ticker")
        share_price = usd(share_info["price"])
        return render_template("quoted.html", symbol=symbol, share_price=share_price)



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        count = db.execute(f'SELECT * FROM "users" WHERE username = "{username}"')
        if (username == ""):
            return apology("Please enter valid username.")
        elif (len(count) > 0):
            return apology("Username already taken.")
        elif (request.form.get("password") != (request.form.get("confirmation"))):
            return apology("Password and confirmation did not match.")
        else:
            hashed_password = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
            db.execute("INSERT INTO users (username, hash) VALUES (:username, :hashed_password)", username = username, hashed_password = hashed_password)
            return redirect("/login")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        get_id = session["user_id"]
        stock_database = db.execute("SELECT * FROM stocks")
        owned_stocks = {}

        for stock in stock_database:
            ticker = stock["ticker"]
            holding = db.execute(f"SELECT holding FROM {ticker} WHERE customer_id = {get_id} AND holding > 1")
            if holding:
                owned_stocks[ticker] = holding[0]["holding"]

        return render_template("sell.html", owned_stocks = owned_stocks)

    else:
        get_id = session["user_id"]
        user_info = db.execute(f"SELECT * FROM users WHERE id = {get_id}")
        user_cash = user_info[0]["cash"]
        customer_id = user_info[0]["id"]
        symbol = request.form.get("symbol")
        share_quantity = request.form.get("shares")
        current_share_price = lookup(symbol)["price"]
        total_value_of_sale = float(share_quantity) * current_share_price
        customer_shareholding = db.execute(f"SELECT holding FROM {symbol} WHERE customer_id = {get_id}")
        customer_shareholding = int(customer_shareholding[0]["holding"])
        if (customer_shareholding < int(share_quantity)) or not customer_shareholding:
            return apology("You tried to sell more shares than you hold.")
        else:
            new_customer_shareholding = customer_shareholding - int(share_quantity)
            db.execute(f"UPDATE {symbol} SET holding = {new_customer_shareholding} WHERE customer_id = {get_id}")
            db.execute(f"UPDATE users SET cash = {user_cash + total_value_of_sale}")
            db.execute("INSERT INTO trades (customer_id, action, stock, quantity, price, total_value) VALUES (:customer_id, :action, :stock, :quantity, :price, :total_value)", customer_id = customer_id, action = "SELL", stock = symbol, quantity = int(share_quantity), price = current_share_price, total_value = total_value_of_sale)
            return render_template("sold.html", share_quantity = share_quantity, stock = symbol, total_price = usd(total_value_of_sale))


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
