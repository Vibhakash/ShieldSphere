from database import engine
from sqlalchemy import text

def add_2fa_columns():
    """Add 2FA columns to users table"""
    try:
        with engine.connect() as conn:
            # Add twofa_secret column
            conn.execute(text("ALTER TABLE users ADD COLUMN twofa_secret VARCHAR"))
            # Add is_2fa_enabled column
            conn.execute(text("ALTER TABLE users ADD COLUMN is_2fa_enabled BOOLEAN DEFAULT FALSE"))
            conn.commit()
            print("✅ 2FA columns added successfully!")
    except Exception as e:
        if "already exists" in str(e).lower():
            print("ℹ️ 2FA columns already exist")
        else:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    add_2fa_columns()