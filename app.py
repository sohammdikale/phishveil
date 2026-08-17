import os
import joblib
import numpy as np
from flask import Flask, jsonify, render_template, request
from feature_extractor import FEATURE_NAMES, extract_features

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024

model = joblib.load(os.path.join(BASE_DIR, 'phishing_model.pkl'))
model_columns = joblib.load(os.path.join(BASE_DIR, 'model_columns.pkl'))
if list(model_columns) != FEATURE_NAMES:
    raise RuntimeError('The feature extractor order does not match model_columns.pkl.')

classes = list(getattr(model, 'classes_', [0, 1]))
class_lookup = {str(label).strip().lower(): label for label in classes}
LEGITIMATE_LABEL = class_lookup.get('legitimate', 1 if 1 in classes else classes[-1])
PHISHING_LABEL = class_lookup.get('phishing', 0 if 0 in classes else classes[0])

@app.get('/')
def index():
    return render_template('index.html')

@app.get('/about')
def about():
    return render_template('about.html', feature_count=len(model_columns), model_name=type(model).__name__)

@app.post('/api/scan')
def scan():
    payload = request.get_json(silent=True) or {}
    raw_url = str(payload.get('url',''))[:2048]
    try:
        values, feature_map, details = extract_features(raw_url, fetch_page=True)
        X = values.reshape(1, -1)
        prediction = model.predict(X)[0]
        probabilities = model.predict_proba(X)[0] if hasattr(model, 'predict_proba') else None
        is_legitimate = prediction == LEGITIMATE_LABEL
        if probabilities is not None:
            class_index = classes.index(prediction)
            confidence = float(probabilities[class_index]) * 100
            phishing_index = classes.index(PHISHING_LABEL)
            phishing_probability = float(probabilities[phishing_index]) * 100
        else:
            confidence = 100.0
            phishing_probability = 0.0 if is_legitimate else 100.0

        risk = 'safe' if phishing_probability < 35 else ('suspicious' if phishing_probability < 70 else 'dangerous')
        reasons = build_reasons(feature_map, details)
        return jsonify({
            'ok': True, 'prediction': 'Legitimate' if is_legitimate else 'Phishing',
            'risk': risk, 'confidence': round(confidence, 2),
            'phishing_probability': round(phishing_probability, 2),
            'details': details, 'reasons': reasons,
            'disclaimer': 'This is an academic ML prediction, not a security guarantee. Do not enter passwords or payment details based only on this result.'
        })
    except ValueError as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 400
    except Exception:
        app.logger.exception('Scan failed')
        return jsonify({'ok': False, 'error': 'The URL could not be analysed. Check it and try again.'}), 500


def build_reasons(f, d):
    reasons = []

    # FIX: a positive, domain-age-based reason. Previously there was no
    # signal that could counterbalance the negative-leaning checks below
    # for long-established legitimate domains.
    if f.get('domain_age', 0) >= 1825:
        reasons.append({'type': 'positive', 'text': 'The domain has been registered for several years.'})

    if d['uses_https']:
        reasons.append({'type':'positive','text':'The URL uses HTTPS.'})
    else:
        reasons.append({'type':'negative','text':'The URL does not use HTTPS.'})
    if f['ip']:
        reasons.append({'type':'negative','text':'The hostname is an IP address rather than a normal domain.'})
    if f['shortening_service']:
        reasons.append({'type':'negative','text':'A URL-shortening service hides the final destination.'})
    if f['phish_hints'] >= 2:
        reasons.append({'type':'negative','text':'The URL contains several account or verification-related terms.'})
    if f['nb_subdomains'] >= 3:
        reasons.append({'type':'negative','text':'The hostname contains an unusually deep subdomain structure.'})
    if f['suspecious_tld']:
        reasons.append({'type':'negative','text':'The top-level domain is frequently associated with disposable or abusive sites.'})
    if f['punycode']:
        reasons.append({'type':'negative','text':'The hostname contains Punycode, which can visually imitate other domains.'})
    if f['login_form'] and f['external_favicon']:
        reasons.append({'type':'negative','text':'A login form appears alongside externally hosted branding resources.'})

    # FIX: surface the external-resource ratio as an explicit reason so
    # it's visible in the UI instead of only silently influencing the
    # model score. Threshold set high (70%) so it only fires for pages
    # that are genuinely resource-heavy from other domains, not every
    # site that uses a couple of external scripts.
    if f.get('ratio_extHyperlinks', 0) >= 70:
        reasons.append({'type':'negative','text':'A large share of the page\'s links point to other domains.'})

    if not reasons:
        reasons.append({'type':'neutral','text':'No single obvious indicator dominated the scan; the model combined all available features.'})
    return reasons[:5]

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)