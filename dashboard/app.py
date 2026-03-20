from flask import Flask, render_template, jsonify
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.decision_engine import DecisionEngine

app = Flask(__name__)

engine = DecisionEngine()


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/scan")
def scan_alerts():

    incidents = engine.scan_alerts()

    return jsonify({
        "count": len(incidents),
        "incidents": incidents
    })


@app.route("/api/incidents")
def get_incidents():

    incidents = engine.get_incidents()

    return jsonify(incidents)


if __name__ == "__main__":
    app.run(debug=True)