from flask import Blueprint, request, jsonify
from app.services.tls_analyzer import TLSAnalyzer

api = Blueprint('api', __name__)

@api.route('/analyze-tls', methods=['GET'])
def analyze_tls():
    try:
        analyzer = TLSAnalyzer()
        results = analyzer.analyze_connection()
        return jsonify({"tls_info": results})
    except Exception as e:
        print(f"Error in analyze_tls: {str(e)}")
        return jsonify({'error': str(e)}), 500