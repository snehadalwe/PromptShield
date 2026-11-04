"""Demo Target HTTP Server.

=============================================================================
CONCEPT: Why expose our demo targets as a REST API?
=============================================================================
In real-world security engagements, penetration testers rarely have access to
the Python code of the chatbot. Chatbots are deployed as microservices behind
REST APIs (e.g., Slackbots, website widgets, mobile backends).

By wrapping our WeakBot and HardenedBot inside a Flask REST API, PromptShield
can treat them as black-box HTTP targets—exactly like a real commercial chatbot.
"""

from flask import Flask, request, jsonify
from promptshield.demo_target.weak_bot import WeakBot
from promptshield.demo_target.hardened_bot import HardenedBot

app = Flask("promptshield_demo_target")

# Initialize both bot variants
weak_bot = WeakBot(use_mock=True)
hardened_bot = HardenedBot(use_mock=True)


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint to verify the server is running."""
    return jsonify({
        "status": "healthy",
        "service": "PromptShield Demo Target Chatbot",
        "supported_modes": ["weak", "hardened"]
    }), 200


@app.route("/chat", methods=["POST"])
def chat():
    """Chat endpoint supporting both 'weak' and 'hardened' modes.

    Request JSON payload:
    {
        "message": "User query string",
        "mode": "weak" | "hardened"  (default: "weak")
    }

    Response JSON:
    {
        "response": "Bot response text",
        "bot_type": "weak" | "hardened",
        "filter_triggered": null | "description"
    }
    """
    data = request.get_json(silent=True) or {}
    user_prompt = data.get("message", "").strip()
    mode = data.get("mode", "weak").lower()

    if not user_prompt:
        return jsonify({"error": "Missing 'message' field in JSON request"}), 400

    if mode == "hardened":
        result = hardened_bot.chat(user_prompt)
    else:
        result = weak_bot.chat(user_prompt)

    return jsonify(result), 200


def run_server(host: str = "127.0.0.1", port: int = 5000, debug: bool = False):
    """Starts the Flask demo server."""
    print("=" * 60)
    print(" 🧬 PromptShield Demo Target Chatbot Service")
    print("=" * 60)
    print(f"[*] Server running at http://{host}:{port}")
    print("[*] Endpoints:")
    print("    - GET  /health")
    print("    - POST /chat   (JSON body: {'message': '...', 'mode': 'weak'|'hardened'})")
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_server()
