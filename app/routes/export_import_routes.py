from flask import Blueprint
from app.controllers.export_import_controller import ExportImportController

export_import_bp = Blueprint("export_import", __name__)

@export_import_bp.route("/export/<entity_type>", methods=["GET"])
def export_entity(entity_type):
    return ExportImportController.export_entity(entity_type)

@export_import_bp.route("/import/<entity_type>", methods=["POST"])
def import_entity(entity_type):
    return ExportImportController.import_entity(entity_type) 