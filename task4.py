import json
from jsonschema import validate, ValidationError


DATA_FILE = "result_task_2.json"
SCHEMA_FILE = "json_schema.json"


def main():
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
        schema = json.load(f)

    try:
        validate(instance=data, schema=schema)
        print("Валидация пройдена успешно")

    except ValidationError as e:
        print("Ошибка валидации:")
        print(f"Сообщение: {e.message}")
        print(f"Путь: {list(e.absolute_path)}")
        print(f"Элемент: {e.instance}")


if __name__ == "__main__":
    main()