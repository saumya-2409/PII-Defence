import pandas as pd
import re
import json
import sys

pii_patterns = {
    'phone': r'\b\d{10}\b',
    'aadhar': r'\b\d{12}\b',
    'passport': r'\b[A-PR-WY][1-9]\d{6}\b',
    'upi': r'\b[\w.-]+@[\w]+\b',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
}

combo_keys = ['name', 'email', 'address', 'device_id', 'ip_address']

def mask_value(key, value):
    if key == 'phone':
        return value[:2] + 'XXXXXX' + value[-2:]
    if key == 'aadhar':
        return value[:4] + 'XXXXXX' + value[-2:]
    if key == 'passport':
        return value[0] + 'XXXXXXX'
    if key == 'upi':
        return '[REDACTED_UPI]'
    if key == 'email':
        parts = value.split('@')
        return parts[0][:2] + 'XXX@' + parts[1] if len(parts) == 2 else '[REDACTED_EMAIL]'
    if key == 'ip_address':
        return 'XXX.XXX.XXX.XXX'
    if key == 'name':
        return ' '.join([x[0] + 'XXX' for x in value.split()])
    if key == 'address':
        return '[REDACTED_ADDRESS]'
    if key == 'device_id':
        return '[REDACTED_DEVICE_ID]'
    return '[REDACTED]'

def detect_pii(record):
    pii_found = False
    pii_keys = set()

    for key, value in record.items():
        if not isinstance(value, str):
            continue
        value_str = str(value)
        for pii_key, pattern in pii_patterns.items():
            if re.search(pattern, value_str):
                pii_found = True
                pii_keys.add(pii_key)
        if key in ['aadhar', 'passport', 'upi_id', 'phone']:
            pii_found = True
            pii_keys.add(key)
    combo_present = [k for k in combo_keys if k in record]
    if len(combo_present) >= 2:
        pii_found = True
        pii_keys.update(combo_present)

    return pii_found, pii_keys

def redact_record(record, pii_keys):
    redacted = {}
    for key, value in record.items():
        if key in pii_keys or (
            isinstance(value, str) and any(re.search(pii_patterns.get(k, ''), value) for k in pii_keys if k in pii_patterns)
        ):
            redacted[key] = mask_value(key, str(value))
        else:
            redacted[key] = value
    return redacted

def main(input_csv):
    df = pd.read_csv(input_csv)
    output_data = []

    for _, row in df.iterrows():
        try:
            data = json.loads(row['data_json'])
        except json.JSONDecodeError:
            output_data.append({
                'record_id': row['record_id'],
                'redacted_data_json': '{}',
                'is_pii': False
            })
            continue

        is_pii, pii_keys = detect_pii(data)
        redacted_data = redact_record(data, pii_keys) if is_pii else data

        output_data.append({
            'record_id': row['record_id'],
            'redacted_data_json': json.dumps(redacted_data),
            'is_pii': is_pii
        })

    output_df = pd.DataFrame(output_data)
    output_df.to_csv('pii_defence_output.csv', index=False)
    print("Output written")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pii_defence.py iscp_pii_dataset.csv")
    else:
        main(sys.argv[1])
