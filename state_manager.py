import os
import json

def get_state_filepath(target, output_dir="."):
    """Constructs the path for a target's state file."""
    filename = f"{target.replace('.', '_')}_state.json"
    return os.path.join(output_dir, filename)

def save_state(target, output_dir, state_data):
    """
    Saves the current scan state to a JSON file.
    """
    filepath = get_state_filepath(target, output_dir)
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(state_data, f, indent=4)
        print(f"[+] Scan state saved to {filepath}")
    except IOError as e:
        print(f"[!] Error saving state file: {e}")

def load_state(target, output_dir):
    """
    Loads a previously saved scan state from a JSON file.
    """
    filepath = get_state_filepath(target, output_dir)
    if os.path.exists(filepath):
        print(f"[+] Found existing state file: {filepath}")
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            print(f"[!] Error loading or parsing state file: {e}. Starting fresh.")
            return None
    return None
