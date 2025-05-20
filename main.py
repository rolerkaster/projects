from app import create_app
from migrations.migrations import run_migrations
from migrations.seeds import seed_data

if __name__ == '__main__':
    run_migrations()
    seed_data()
    
    app = create_app()
    app.run(debug=True)