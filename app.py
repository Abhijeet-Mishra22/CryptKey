from flask import Flask, render_template, request, jsonify
import hashlib
import random
import re

app = Flask(__name__)

# ==========================================
# SECURITY HEADERS (WITH CSP FIX FOR LOGOS)
# ==========================================
@app.after_request
def add_security_headers(response):
    """Adds essential HTTP security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # CSP: Allowed google.com and gstatic.com to render website favicons dynamically
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https://www.google.com https://*.gstatic.com https://icons.duckduckgo.com; "
        "connect-src 'self' https://api.pwnedpasswords.com;"
    )
    return response


# ==========================================
# DETERMINISTIC PASSWORD GENERATION
# ==========================================
def generate_advanced_password(master_password, target_site, version, length, use_upper, use_lower, use_nums, use_syms):
    """
    Generates a deterministic password using PBKDF2 as a seed for a PRNG.
    Includes Versioning to allow password rotation without changing the master key.
    """
    # Inject the version into the salt
    salt = f"{target_site.strip().lower()}::v{version}".encode('utf-8')
    password = master_password.encode('utf-8')
    
    # Generate cryptographic hash (310,000 iterations for brute-force resistance)
    derived_key = hashlib.pbkdf2_hmac('sha256', password, salt, 310000, dklen=32)
    
    # Convert hash to seed for PRNG
    seed_int = int.from_bytes(derived_key, 'big')
    rng = random.Random(seed_int)
    
    # Build character pool
    pool = ""
    if use_upper: pool += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if use_lower: pool += "abcdefghijklmnopqrstuvwxyz"
    if use_nums: pool += "0123456789"
    if use_syms: pool += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    if not pool: # Fallback safety
        pool = "abcdefghijklmnopqrstuvwxyz"
        use_lower = True

    # Ensure at least one character of each requested type
    result = []
    if use_upper: result.append(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
    if use_lower: result.append(rng.choice("abcdefghijklmnopqrstuvwxyz"))
    if use_nums: result.append(rng.choice("0123456789"))
    if use_syms: result.append(rng.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))
    
    # Fill remaining length
    while len(result) < length:
        result.append(rng.choice(pool))
        
    # Shuffle deterministically so guaranteed chars aren't always first
    rng.shuffle(result)
    return "".join(result)[:length]


# ==========================================
# ROUTES
# ==========================================
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/generate', methods=['POST'])
def generate():
    data = request.get_json()
    
    master_password = data.get('masterPassword', '')
    target_site = data.get('targetSite', '')
    version = int(data.get('version', 1))
    length = int(data.get('length', 16))
    use_upper = data.get('uppercase', True)
    use_lower = data.get('lowercase', True)
    use_nums = data.get('numbers', True)
    use_syms = data.get('symbols', True)
    
    # ERROR HANDLING & VALIDATION
    if not master_password or not target_site:
        return jsonify({'error': 'Master password and target domain are required.'}), 400
        
    if not (8 <= length <= 64):
        return jsonify({'error': 'Password length must be between 8 and 64 characters.'}), 400
        
    if version < 1 or version > 999:
        return jsonify({'error': 'Version must be between 1 and 999.'}), 400
        
    if not (use_upper or use_lower or use_nums or use_syms):
        return jsonify({'error': 'At least one character type must be selected.'}), 400
        
    try:
        generated = generate_advanced_password(
            master_password, target_site, version, length, use_upper, use_lower, use_nums, use_syms
        )
        return jsonify({
            'success': True,
            'generatedPassword': generated
        })
    except Exception as e:
        return jsonify({'error': 'Cryptographic synthesis failed. Please try again.'}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
