from setuptools import setup
from Cython.Build import cythonize

setup(
    name="my_gui_app",
    ext_modules=cythonize(
        ["gui.pyx", "copy_to_local_at_type.pyx", "Api_search3.pyx", "class_resolver.pyx"],  # Укажите все .pyx файлы
        compiler_directives={'language_level': "3str"}
    ),
    zip_safe=False,
    install_requires=['requests', 'tkinter', 'os', 'shutil', 're', 'time', 'subprocess', 'sys'],  # Добавьте другие зависимости, если есть
)
