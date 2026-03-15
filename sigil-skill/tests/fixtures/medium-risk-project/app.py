"""Application with moderate risk patterns — TEST FIXTURE ONLY."""
import os
import subprocess


def run_command(cmd: str) -> str:
    result = subprocess.run(cmd.split(), capture_output=True, text=True)
    return result.stdout


def get_config() -> dict:
    return {
        "api_key": os.environ.get("API_KEY", ""),
        "db_url": os.environ.get("DATABASE_URL", ""),
    }


if __name__ == "__main__":
    config = get_config()
    print(run_command("echo hello"))
