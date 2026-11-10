
import main

with main.SessionLocal() as session:
    records = session.query(main.SecureRecord).all()

    if not records:
        print("No records found. Run the create-record test first.")
    else:
        for record in records:
            print("Record ID:", record.id)
            print("Owner:", record.owner)
            print("Stored note:", record.encrypted_note)
            print("Encrypted field contains readable test note:",
                  "Private note" in record.encrypted_note)
            print("-" * 40)
