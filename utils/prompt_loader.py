def load_prompt(prompt_path):

    with open(prompt_path, "r", encoding="utf-8") as file:

        return file.read()


def load_application(application_path):

    with open(application_path, "r", encoding="utf-8") as file:

        return file.read()