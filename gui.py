import ipaddress
import time
import os
import threading
from re import sub as rs
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog, Toplevel

# from paramiko.common import four_byte

import Api_search3, copy_to_local_at_type
from datetime import datetime
import shutil

from unpack_group_gui import run_og_viewer

# import glossary

GLOSSARY_TEXT = """                     Здесь представлено описание функций программы.

Поиск:
  • Source IP — исходный IP-адрес или сеть (пустое поле означает 'any').
  • Destination IP — целевой IP-адрес или сеть (пустое поле означает  'any').
  • Реверc IP - кнопка меняющая местами объекты полей "Source IP" и "Destination IP".
  • Строгое соответствие — если включено, ищется точное совпадение ip-адреса. Сети всегда ищутся строго.
  • Source or Destination — режим, который ищет ip-адрес сразу в обоих направлениях.
        Если указать адрес в "Source IP", то будет найдено соответствие сперва ip -> any, затем any -> ip.
        Если указать адрес в "Destination IP", то наоборот, сперва any -> ip, затем ip -> any.
        В этом режиме нельзя указать адрес сразу в обоих полях.

Чекбоксы:
  • Фильтр по регионам - позволяет выбрать конкретный регион поиска ACL.
        Чекбокс "Все" активирует/деактивирует все регионы.
  • Фильтр по одобрудованию - позволяет выбрать конкретный тип устройств для поиска ACL.
        Чекбокс "Все" активирует/деактивирует все устройства. 
    Должен быть выбран хотя бы один регион и устройство. В противном случае будет показано предупреждение.   


Сохранение:
  • Сохранить на диск — кнопка открывает диалоговое окно для сохранения вывода данных.
        Если поле вывода пустое будет выведено предупреждение.

Удаление:
  • Удалить папку конфигураций — кнопка удаляет папку с конфигурациями "сollected_files_clear".
        После удаления программа вернется в состояние ввода логина/пароля gitlab и netbox Token для повторной загрузки.

Горячие клавиши:
  • Tab - перемещение между элементами.
  • Enter/Space (пробел) - выбор чекбоксов/активация действия кнопок.
  • Ctrl + Shift + S - Сохранение вывода данных.
  • Ctrl + Shift + Q - Быстрое сохранение вывода данных. Данные сохраняются в папку расположения программы.
  • Ctrl + Shift + D - Удаление папки с конфигурациями устройств.
  • Ctrl + Shift + F - Активация поиска/действие кнопки "Поиск".
  • Ctrl + Shift + E - Удаление IP/действие кнопки "Сброс IP".
  • Ctrl + Shift + R - Реверс IP/действие кнопки "Реверс IP".
  • F1 - Вызов справки/Действие кнопки "Инфо"
  • Escape - Закрыть окно.


Версия: 1.19.2 / 16.02.26
"""

CONFIG_DIR = "collected_files_clear"

UES = {
    "ЛВС": "ЛВС",
    "ЦОД": "ЦОД",
}

# PREFIX_LABELS = {
#     "Волга": "PRNG-DC",
#     "ДВ": "DV",
#     "СЗ": "SZSP-DC",
#     "Центр": "CEMO-DC",
#     "КЦ": "CEMS-DC",
#     "Урал": "UREK-DC",
#     "Юг": "UFKR-DC",
#     "Сибирь": "SI",
# }


PREFIX_LABELS = {
    "Волга": "PR",
    "ДВ": "DV",
    "СЗ": "SZ",
    "Центр": "CE",
    "КЦ": "CE",
    "Урал": "UR",
    "Юг": "UF",
    "Сибирь": "SI",
}

PLATFORM_GROUPS = {
    "Cisco ASA": ["Cisco ASA"],
    "Cisco Firepower": ["Cisco FXOS"],
    "Cisco IOS": ["Cisco IOS"],
    "Cisco IOS XE": ["Cisco IOS XE"],
    "Cisco NX-OS": ["Cisco NX-OS"],
    "FortiOS": ["FortiOS"],
    "Huawei": ["Huawei VRP", "Huawei VRP 2403"],
    "Eltex":["Eltex"],
    "Eltex ESR":["Eltex ESR"],
    "HP ProCurve/HPE":["HPE Comware",'HP ProCurve',"HPE OfficeConnect", "HPE Comware 1910"],
    "Прочие устройства": [   # всё остальное
        "B4COM BCOM-OS-DC", "EdgeCore", "IBM_Lenovo Network OS",
        "Dell Networking OS", "Juniper Junos", "Cisco IOS XR", "Cisco PIX"
    ],
}

def bind_enter_to_button(self, button):
    """Делает кнопку активируемой клавишей Enter."""
    button.bind("<Return>", lambda event: button.invoke())      # Enter с основного блока
    button.bind("<KP_Enter>", lambda event: button.invoke())

def add_placeholder(entry, placeholder="any", color="gray"):
    """Добавляет серый placeholder, который исчезает при вводе."""
    # default_fg = entry.cget("fg")

    def on_focus_in(event):
        if entry.get() == placeholder and entry.cget("fg") == "gray":
            entry.delete(0, tk.END)
            # entry.insert(0, placeholder)
            entry.config(fg="black")
        if entry.get() == placeholder and entry.cget("fg") == "black":
            # entry.delete(0, tk.END)
            # entry.insert(0, placeholder)
            # entry.delete(0, tk.END)
            entry.config(fg="gray")
        if entry.get() != placeholder and entry.cget("fg") == "gray":
            # entry.delete(0, tk.END)
            entry.config(fg="black")


    def on_focus_out(event):
        if not entry.get().strip() or entry.get() == "any":
            entry.delete(0, tk.END)
            entry.insert(0, placeholder)
            entry.config(fg="gray")
        if entry.get() != "any":
            # entry.delete(0, tk.END)
            # entry.insert(0, placeholder)
            entry.config(fg="black")
        if entry.get() != "any" and entry.cget("fg") == "gray":
            # entry.delete(0, tk.END)
            # entry.insert(0, placeholder)
            entry.config(fg="black")
        # if not entry.get() == placeholder and entry.cget("fg") == "black":
        #     entry.delete(0, tk.END)
        #     entry.config(fg="gray")

    # Инициализация placeholder при запуске
    entry.insert(0, placeholder)
    entry.config(fg="gray")

    # Привязки событий
    entry.bind("<FocusIn>", on_focus_in)
    entry.bind("<FocusOut>", on_focus_out)

def limit_entry_length(entry_widget, max_length=50):
    """Запрещает ввод строк длиннее max_length символов."""
    def on_validate(P):
        return len(P) <= max_length
    vcmd = (entry_widget.register(on_validate), "%P")
    entry_widget.config(validate="key", validatecommand=vcmd)

def toggle_all(group_vars, master_var):
    """
    Устанавливает значение master_var (True/False) для всех чекбоксов в группе
    """
    state = master_var.get()
    for var in group_vars:
        var.set(state)

def update_master(master_var, group_vars):
    """
    Обновляет главный чекбокс: если все выбраны — True, иначе False
    """
    master_var.set(all(v.get() for v in group_vars))

def select_all(event):
    event.widget.select_range(0, tk.END)   # выделить весь текст
    event.widget.icursor(tk.END)           # курсор в конец
    return "break"

def validate_ip_or_network(value: str) -> bool:
    if not value or value.lower() == "any":
        return True
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def fix_entry_shortcuts(entry_widget):
    # Ctrl+A — выделить всё
    def select_all(event=None):
        entry_widget.focus_set()
        entry_widget.selection_range(0, tk.END)
        return "break"

    # Ctrl+C
    def copy(event=None):
        entry_widget.event_generate("<<Copy>>")
        return "break"

    # Ctrl+X
    def cut(event=None):
        entry_widget.event_generate("<<Cut>>")
        return "break"

    # Ctrl+V — вставка с заменой выделенного
    def paste(event=None):
        try:
            selection = entry_widget.selection_get()
            # если выделен текст — удалить его
            entry_widget.delete("sel.first", "sel.last")
        except tk.TclError:
            # ничего не выделено — просто вставляем в позицию курсора
            pass
        entry_widget.event_generate("<<Paste>>")
        return "break"

    # биндим все варианты (нижний и верхний регистр)
    entry_widget.bind("<Control-a>", select_all)
    entry_widget.bind("<Control-A>", select_all)
    entry_widget.bind("<Control-c>", copy)
    entry_widget.bind("<Control-C>", copy)
    entry_widget.bind("<Control-v>", paste)
    entry_widget.bind("<Control-V>", paste)
    entry_widget.bind("<Control-x>", cut)
    entry_widget.bind("<Control-X>", cut)

# 999
class ParserApp:
    # LIGHT_BG = "#f0f0f0"
    def __init__(self, root):
        self.all_regions_var = None
        self.root = root
        self.root.title("ACL Parser. Версия для AltLinux.")
        self.root.geometry("1200x835")
        self.root.configure(bg="#f0f0f0")
        self.root.resizable(True, True)
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        if not os.path.exists(CONFIG_DIR) or not os.listdir(CONFIG_DIR):
            self.open_download_window()
        else:
            self.build_main_window()
            self.create_menu()

    def app_exit(self):
        self.root.destroy()

    def show_version(self):
        messagebox.showinfo("Версия", "1.19.4. 11 марта 2026 г.")

    def create_menu(self):
        # print("окно")
        from tkinter import font
        # menubar = tk.Menu(self.root)
        # menubar = tk.Menu(self.root, bg="#f0f0f0", fg="black")

        # --- Программа ---
        menu_font = font.Font(family="Arial", size=9)
        bg_color = "#f0f0f0"
        fg_color = "black"

        menubar = tk.Menu(self.root, bg=bg_color, fg=fg_color, font=menu_font)
        program_menu = tk.Menu(menubar, tearoff=0, bg=bg_color, fg=fg_color, activebackground=bg_color)
        help_menu = tk.Menu(menubar, tearoff=0, bg=bg_color, fg=fg_color, activebackground=bg_color)

        menubar = tk.Menu(self.root, bg="#f0f0f0", fg="black",font=menu_font) # фон и текст

        # program_menu = tk.Menu(menubar, tearoff=0, bg="#f0f0f0", fg="black") # activebackground="#d9d9d9"
        # МЕНЮ ПРОГРАММА
        menubar.add_cascade(label="Программа", menu=program_menu)
        menubar.add_cascade(label="Справка", menu=help_menu)
        # help_menu = tk.Menu(menubar, tearoff=0, bg="#f0f0f0", fg="black", activebackground="#d9d9d9")
        # program_menu = tk.Menu(menubar, tearoff=0)
        # program_menu = tk.Menu(menubar, tearoff=0, bg="#f0f0f0", bd=0, activebackground="#d9d9d9")
        # program_menu.add_command(label="Выход", command=self.app_exit, background="#f0f0f0")
        # меню1
        program_menu.add_command(label="Сохранить на диск", command=self.save_output, font=menu_font)
        program_menu.add_command(label="Удалить конфигурацию", command=self.delete_config_folder, font=menu_font)
        program_menu.add_command(label="OG Viewer", command=run_og_viewer, font=menu_font)
        program_menu.add_command(label="Выход", command=self.app_exit, font=menu_font)
        # --- МЕНЮ СПРАВВКА ---
        # help_menu = tk.Menu(menubar, tearoff=0,bg="#f0f0f0", fg="black",font=menu_font)
        help_menu.add_command(label="Глоссарий", command=self.show_glossary, font=menu_font)
        help_menu.add_command(label="Версия", command=self.show_version,font=menu_font)


        # прикрепляем к окну
        self.root.config(menu=menubar)
    def show_glossary(self):
        """Открыть модальное окно с глоссарием (только для чтения)."""
        text = GLOSSARY_TEXT

        win = Toplevel(self.root)
        win.title("Глоссарий")
        win.transient(self.root)  # ставим над основным окном
        win.resizable(True, True)
        win.grab_set()
        win.focus_set()
        win.bind("<Escape>", lambda e: win.destroy())
        # делаем модальным (чтобы нельзя было работать с main пока открыт)
        # Опционально: фиксированный размер: win.geometry("600x400")

        # scrolled text
        st = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=92, height=38.5)
        st.pack(fill="both", expand=True, padx=1, pady=1)
        st.insert("1.0", text)
        st.config(state="disabled")  # только для чтения


        # Центрируем окно над родителем
        self.root.update_idletasks()
        win.update_idletasks()
        rw = self.root.winfo_width()
        rh = self.root.winfo_height()
        rx = self.root.winfo_rootx()
        ry = self.root.winfo_rooty()
        ww = win.winfo_reqwidth()
        wh = win.winfo_reqheight()
        x = rx + (rw - ww) // 2
        y = ry + (rh - wh) // 2
        win.geometry(f"+{x}+{y}")

    def save_output(self):
        text = self.output.get("1.0", tk.END).strip()
        if not text:
                # Окно предупреждения, если поле вывода пустое
                messagebox.showinfo("Ой!", "Поле вывода пустое.")
                return
        """Сохранить содержимое окна вывода в текстовый файл"""
        # берём введённые IP (или any если пусто)
        src_ip = self.src_entry.get().strip() or "any"
        dst_ip = self.dst_entry.get().strip() or "any"

        def sanitize(name):
            return rs(r'[\\/:*?"<>|]', '_', name)


        src_ip = sanitize(src_ip)
        dst_ip = sanitize(dst_ip)
        # 123

        # формируем имя файла: src-dst-dd-mm-yyyy-hh-mm.txt
        timestamp = datetime.now().strftime("%d-%m-%Y-%H-%M")
        ss = self.src_or_dst_var.get()
        cc = self.strict_var.get()
        # print(ss)
        adddata1=adddata2=""
        if ss: adddata1="SOD-"
        if cc: adddata2="Strict-"
        filename = f"{adddata2}{adddata1}{src_ip}-{dst_ip}-{timestamp}.txt"
        # else: filename = f"{src_ip}-{dst_ip}-{timestamp}.txt"

        # спрашиваем у пользователя, куда сохранить (по умолчанию в текущую папку)
        filepath = filedialog.asksaveasfilename(
            initialfile=filename,
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not filepath:
            return  # пользователь отменил
        try:
            text = self.output.get("1.0", tk.END).strip()
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(text)
            messagebox.showinfo("Успех", f"Файл сохранён:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить файл:\n{e}")

    def delete_config_folder(self):
        """Удаляет папку collected_files_clear после подтверждения"""
        if not os.path.exists(CONFIG_DIR):
            messagebox.showinfo("Инфо.",
                                "Папка конфигураций отсутствует.")
            return

        # Окно подтверждения
        answer = messagebox.askyesno("Точно удалить?",
                                     "Удалить папку конфигураций?\n"
                                     "Все скачанные файлы будут удалены.")
        if not answer:
            return  # пользователь нажал «Нет»

        try:
            shutil.rmtree(CONFIG_DIR)
            time.sleep(0.5)
            messagebox.showinfo("Успех!", "Папка конфигураций удалена.")
        except Exception as e:
            messagebox.showerror("Ошибка!", f"Не удалось удалить папку:\n{e}")
            return

        # Закрываем текущее окно main и открываем окно скачивания
        for widget in self.root.winfo_children():
            widget.destroy()
        self.open_download_window()

    def update_placeholder(self, entry, text="any"):
        """Устанавливает серый placeholder."""
        entry.insert(0, text)
        entry.config(fg="gray")
    def reverse_ips(self):
        if not self.src_entry.get().strip():
            add_placeholder(self.src_entry, "any","gray")
        if not self.dst_entry.get().strip():
            add_placeholder(self.dst_entry, "any","gray")
        # validate_ip_or_network()
        """Меняет местами значения Source IP и Destination IP."""
        src_value = self.src_entry.get()
        dst_value = self.dst_entry.get()

        # if not validate_ip_or_network(src_value):
        #     messagebox.showerror("Ошибка!", f"Неверный формат Source IP: {src_value}")
        #     # add_placeholder(src_value, "any", "gray")
        #     return
        # if not validate_ip_or_network(dst_value):
        #     messagebox.showerror("Ошибка!", f"Неверный формат Destination IP: {dst_value}")
        #     # add_placeholder(dst_value, "any", "gray")
        #     return

        # Меняем местами
        self.src_entry.delete(0, tk.END)
        self.src_entry.insert(0, dst_value)

        self.dst_entry.delete(0, tk.END)
        self.dst_entry.insert(0, src_value)
        #

    def clear_ips(self):
        self.src_entry.delete(0, tk.END)
        add_placeholder(self.src_entry, "any", "gray")
        self.dst_entry.delete(0, tk.END)
        add_placeholder(self.dst_entry, "any", "gray")

    def bind_enter_to_button(self, button):
        """Делает кнопку активируемой клавишей Enter."""
        button.bind("<Return>", lambda event: button.invoke())  # Enter с основного блока
        button.bind("<KP_Enter>", lambda event: button.invoke())

    def show_temp_popup(self, text):
        """
        Маленькое всплывающее окно, исчезающее через 1 секунду.
        """
        popup = tk.Toplevel(self.root)
        popup.overrideredirect(True)  # убираем рамку и заголовок
        popup.configure(bg="#f0f0f0")

        # Размер и позиция — центр окна
        popup.geometry("+%d+%d" % (self.root.winfo_x() + 200, self.root.winfo_y() + 200))

        label = tk.Label(popup, text=text, bg="#f0f0f0", fg="green", font=("Arial", 11, "bold"))
        label.pack(padx=20, pady=10)

        self.root.update_idletasks()
        main_x = self.root.winfo_x()
        main_y = self.root.winfo_y()
        main_w = self.root.winfo_width()
        main_h = self.root.winfo_height()
        popup.update_idletasks()
        popup_w = popup.winfo_reqwidth()
        popup_h = popup.winfo_reqheight()

        x = main_x + (main_w // 2) - (popup_w // 2)
        y = main_y + (main_h // 2) - (popup_h // 2)
        popup.geometry(f"+{x}+{y}")

        # Автозакрытие через 1 секунду
        popup.after(1000, popup.destroy)

    def quick_save_output(self, event=None):
        """
        Быстрое сохранение вывода без диалога.
        Файл сохраняется рядом с программой под именем src-dst-date.txt
        """
        content = self.output.get("1.0", tk.END).strip()
        if not content:
            messagebox.showinfo("Ой.", "Поле вывода пустое.")
            return

        # Формируем имя файла
        src_ip = self.src_entry.get().strip() or "any"
        dst_ip = self.dst_entry.get().strip() or "any"

        # Заменяем недопустимые символы
        src_ip = src_ip.replace("/", "_").replace("\\", "_")
        dst_ip = dst_ip.replace("/", "_").replace("\\", "_")

        now = datetime.now().strftime("%d-%m-%Y-%H-%M")
        ss = self.src_or_dst_var.get()
        cc = self.strict_var.get()
        # print(ss)
        adddata1=adddata2=""
        if ss: adddata1="SOD-"
        if cc: adddata2="Strict-"
        # filename = f"{src_ip}-{dst_ip}-{now}.txt"
        filename = f"{adddata2}{adddata1}{src_ip}-{dst_ip}-{now}.txt"
        # Сохраняем в текущей директории
        filepath = os.path.join(os.getcwd(), filename)
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception as e:
            messagebox.showerror("Ошибка сохранения", f"Не удалось сохранить файл:\n{e}")
            return

        # Показываем короткое уведомление
        self.show_temp_popup("💾 Сохранено")
    # ---------------- MAIN WINDOW ----------------
    # 1001
    def build_main_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        frame = tk.Frame(self.root,bg="#f0f0f0")
        frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        top_frame = tk.Frame(frame, bg="#f0f0f0")
        top_frame.grid(row=0, column=0, sticky="w")

        # Создаем отдельный фрейм для полей ввода, чтобы лучше контролировать их выравнивание
        input_frame = tk.Frame(frame,bg="#f0f0f0")
        input_frame.grid(in_=top_frame,row=0, column=0, sticky="nw", padx=5, pady=10)  # 🔹 Новый фрейм, прижатый влево

        # Поля ввода
        tk.Label(input_frame, text="Source IP:",bg="#f0f0f0").grid(row=0, column=0, sticky="nw", padx=(10, 5))  #  sticky="w" вместо "e"
        self.src_entry = tk.Entry(input_frame, width=30)
        self.src_entry.grid(row=0, column=1, sticky="nw", padx=5)  # 🔹 Убедимся, что поле прижато влево
        # self.src_entry.bind("<Control-a>", select_all)
        # self.src_entry.bind("<Control-A>", select_all)
        fix_entry_shortcuts(self.src_entry)
        limit_entry_length(self.src_entry, 50)
        add_placeholder(self.src_entry, "any", "gray")

        tk.Label(input_frame, text="Destination IP:",bg="#f0f0f0").grid(row=1, column=0, sticky="nw", padx=(10, 5))  # 🔹 sticky="w" вместо "e"
        self.dst_entry = tk.Entry(input_frame, width=30)
        self.dst_entry.grid(row=1, column=1, sticky="nw", padx=5)
        # self.dst_entry.bind("<Control-a>", select_all)
        # self.dst_entry.bind("<Control-A>", select_all)
        fix_entry_shortcuts(self.dst_entry)
        limit_entry_length(self.dst_entry, 50)
        add_placeholder(self.dst_entry, "any", "gray")



        self.reverse_btn = tk.Button(
            input_frame,
            text="Реверс IP",
            command=self.reverse_ips,
            bg="#e0e0e0"
        )


        self.clear_ip_btn = tk.Button(
            input_frame,
            text="Сброс IP",
            command=self.clear_ips,
            bg="#e0e0e0"
        )

        self.clear_ip_btn.grid(row=2, column=0, columnspan=2, pady=(2, 0), padx=(263, 0))
        self.reverse_btn.grid(row=3, column=0, columnspan=2, pady=(2, 0), padx=(270, 0))
        # reverse_btn.grid(row=1, column=2, padx=(10, 0))

        self.strict_var = tk.BooleanVar(value=False)
        tk.Checkbutton(input_frame, text="Строгое соответствие",bg="#f0f0f0",
                       highlightthickness=1,highlightbackground="#f0f0f0",
                       variable=self.strict_var).grid(row=2, column=0, columnspan=2, sticky="w",
                                                      padx=(0, 5), pady=(5, 0))

        self.src_or_dst_var = tk.BooleanVar(value=False)
        src_or_dst_check = tk.Checkbutton(
            input_frame,
            text="Source or Destination",
            highlightthickness=1,highlightbackground="#f0f0f0",
            bd=0,
            variable=self.src_or_dst_var,
            bg="#f0f0f0"
        )
        src_or_dst_check.grid(row=3, column=0, columnspan=2, sticky="w", padx=(1, 5), pady=(0, 2))


        # 🔹 Группа чекбоксов

        # UES

        frame.grid_columnconfigure(0, weight=1)
        #
        ues_frame = tk.LabelFrame(frame, text="УЭС:",bg="#f0f0f0")
        ues_frame.grid(in_=top_frame,row = 0, column = 1, sticky = "nw", padx = 0)

        self.ues_vars = {}
        col = 0
        row = 0
        for label, ues in UES.items():
            var = tk.BooleanVar(value=True)
            cb = tk.Checkbutton(ues_frame, text=label,bg="#f0f0f0",
                                highlightthickness=1, highlightbackground="#f0f0f0", variable=var)
            cb.grid(row=row, column=col, sticky="w", padx=5)
            self.ues_vars[label] = var
            col += 1
            if col >= 1:  # делаем таблицу 2 строки × 4 столбца
                col = 0
                row += 1
        self.all_ues_var = tk.BooleanVar(value=True)


        prefix_frame = tk.LabelFrame(frame, text="Фильтр по регионам:",bg="#f0f0f0")
        prefix_frame.grid(in_=top_frame, row = 0, column = 2, sticky = "nw", padx = 0)

        self.prefix_vars = {}
        col = 0
        row = 0
        for label, prefix in PREFIX_LABELS.items():
            var = tk.BooleanVar(value=True)
            cb = tk.Checkbutton(prefix_frame, text=label,bg="#f0f0f0",
                                highlightthickness=1, highlightbackground="#f0f0f0", variable=var)
            cb.grid(row=row, column=col, sticky="w", padx=5)
            self.prefix_vars[label] = var
            col += 1
            if col >= 4:  # делаем таблицу 2 строки × 4 столбца
                col = 0
                row += 1
        self.all_regions_var = tk.BooleanVar(value=True)

        all_regions_cb = tk.Checkbutton(
            prefix_frame,
            text="Все",
            highlightthickness=1,highlightbackground="#f0f0f0",
            bg="#f0f0f0",
            variable=self.all_regions_var,
            command=lambda: toggle_all(list(self.prefix_vars.values()), self.all_regions_var)
        )
        all_regions_cb.grid(row=row + 1, column=0, sticky="nw", padx=5, pady=(5, 0))


        self.platform_vars = {}


        platform_frame = tk.LabelFrame(frame, text="Фильтр по оборудованию:",bg="#f0f0f0")
        platform_frame.grid(in_=top_frame, row=0, column=3, sticky="nw",padx=0)

        col, row = 0, 0
        for label in PLATFORM_GROUPS.keys():
            var = tk.BooleanVar(value=True)
            cb = tk.Checkbutton(platform_frame, text=label,bg="#f0f0f0",
                                highlightthickness=1,highlightbackground="#f0f0f0",variable=var)
            cb.grid(row=row, column=col, sticky="w", padx=5)
            self.platform_vars[label] = var
            col += 1
            if col >= 3:  # делаем 3 столбца
                col = 0
                row += 1
        self.all_platforms_var = tk.BooleanVar(value=True)
        all_platforms_cb = tk.Checkbutton(
            platform_frame,
            text="Все",
            highlightthickness=1,highlightbackground="#f0f0f0",
            bg="#f0f0f0",
            variable=self.all_platforms_var,
            command=lambda: toggle_all(list(self.platform_vars.values()), self.all_platforms_var)
        )
        all_platforms_cb.grid(row= row + 1, column=0, sticky="w", padx=5, pady=(5, 0))
        # Кнопка поиска

        btn_frame = tk.Frame(frame, bg="#f0f0f0")
        btn_frame.grid(row=4, column=0, sticky="ew")

        # даём колонке растягиваться
        btn_frame.grid_columnconfigure(0, weight=1)

        self.search_btn = tk.Button(btn_frame, text="Поиск", command=self.run_search)

        # ставим кнопку в центр
        self.search_btn.grid(row=0, column=0)



        self.root.bind("<Control-Shift-f>", lambda event: self.run_search())
        self.root.bind("<Control-Shift-F>", lambda event: self.run_search())
        self.bind_enter_to_button(self.search_btn)
        #1003
        # Окно вывода
        output_frame = tk.Frame(frame, bg="#f0f0f0")
        output_frame.grid(row=5, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)

        # растягивается строка в родителе
        frame.grid_rowconfigure(5, weight=1)

        # растягивается содержимое внутри
        output_frame.grid_rowconfigure(0, weight=1)
        output_frame.grid_columnconfigure(0, weight=1)

        self.output = scrolledtext.ScrolledText(
            output_frame,
            wrap=tk.WORD,
            state="disabled",
            takefocus=0
        )

        self.output.grid(row=0, column=0, sticky="nsew")
        # self.output = scrolledtext.ScrolledText(frame, wrap=tk.WORD,state="disabled",takefocus=0)
        # self.output.grid(row=5, column=0, columnspan=2, sticky="nsew", padx=5)


        # self.save_btn = tk.Button(frame, text="Сохранить на диск", command=self.save_output)
        # self.save_btn.grid(row=6, column=0, columnspan=2, padx=6,pady=(5,0), sticky="w")

        # self.help_btn = tk.Button(frame, text="Инфо", command=self.show_glossary)
        # позиционируй так, как нужно: тут пример - справа от save_btn

        # self.help_btn.grid(row=6,column=1,padx=120, pady=(5,0), sticky="w")
        # self.delete_btn = tk.Button(frame, text="Удалить папку конфигураций",
        #                             command=self.delete_config_folder)
        # self.delete_btn.grid(row=6, column=1, columnspan=2,padx=470, pady=(5, 0), sticky="w")

        # комби
        self.root.bind("<Control-Shift-s>", lambda event: self.save_output())
        self.root.bind("<Control-Shift-S>", lambda event: self.save_output())
        self.root.bind("<Control-Shift-d>", lambda event: self.delete_config_folder())
        self.root.bind("<Control-Shift-D>", lambda event: self.delete_config_folder())
        self.root.bind("<Control-Shift-e>", lambda event: self.clear_ips())
        self.root.bind("<Control-Shift-E>", lambda event: self.clear_ips())
        self.root.bind("<Control-Shift-r>", lambda event: self.reverse_ips())
        self.root.bind("<Control-Shift-R>", lambda event: self.reverse_ips())
        self.root.bind("<F1>", lambda e: self.show_glossary())

        self.root.bind("<Control-Shift-q>", self.quick_save_output)
        self.root.bind("<Control-Shift-Q>", self.quick_save_output)
        self.root.bind("<Escape>", lambda e: self.root.destroy())
        # кнопкиdelete_config_folder
        self.bind_enter_to_button(self.reverse_btn)
        self.bind_enter_to_button(self.clear_ip_btn)
        # self.bind_enter_to_button(self.save_output)
        # self.bind_enter_to_button(self.delete_config_folder)


    def run_search(self):

        self.output.config(state="disabled")
        src_ip = self.src_entry.get().strip() or 'any'
        dst_ip = self.dst_entry.get().strip() or 'any'

        if not validate_ip_or_network(src_ip):
            messagebox.showerror("Ошибка!", f"Неверный формат Source IP: {src_ip}")
            return
        if not validate_ip_or_network(dst_ip):
            messagebox.showerror("Ошибка!", f"Неверный формат Destination IP: {dst_ip}")
            return

        # если поле пустое → заменяем на "any"
        if not src_ip:
            src_ip = "any"
        if not dst_ip:
            dst_ip = "any"
        src_or_dst_mode = self.src_or_dst_var.get()
        # 777
        if src_or_dst_mode and ((src_ip!="any" and dst_ip!="any") or (src_ip=="any" and dst_ip=="any")):
            messagebox.showerror("Ошибка!",
                                 f"Должен быть один адрес в поле Source ИЛИ Destination.")
            return

        # self.output.config(state="normal")

        self.output.config(state="normal")

        # Собираем выбранные префиксы

        # --- блок чекбоксов по УЭС ---
        enabled_ues = [
            UES[label]
            for label, var in self.ues_vars.items()
            if var.get()
        ]

        # print(enabled_ues)
        # enabled_ues = any(var.get() for var in self.ues_vars.values())
        # print(enabled_ues)
        enabled_region_labels = [label for label, var in self.prefix_vars.items() if var.get()]
        enabled_prefixes = [PREFIX_LABELS[label] for label in enabled_region_labels]
        # print(enabled_ues)
        if not enabled_ues:
            messagebox.showerror("Ошибка", "Нужно выбрать УЭС!")
            self.all_ues_var.set(False)
            self.output.config(state="disabled")
            return

        if not enabled_prefixes:
            messagebox.showerror("Ошибка", "Нужно выбрать хотя бы один регион!")
            self.all_regions_var.set(False)
            return

        self.output.delete("1.0", tk.END)
        self.output.config(state="normal")
        if src_or_dst_mode:
            self.output.insert(tk.END, f"Запуск поиска ACL для {src_ip} → {dst_ip} и {dst_ip} → {src_ip}\n\n")
        else:
            self.output.insert(tk.END, f"Запуск поиска ACL для {src_ip} → {dst_ip}\n\n")
        self.output.insert(tk.END, f"Выбранные УЭС: {', '.join(enabled_ues)}\n")
        self.output.see(tk.END)
        # self.output.insert(tk.END, f"Запуск поиска ACL для {src_ip} → {dst_ip}\n\n")
        self.output.insert(tk.END, f"Выбранные регионы: {', '.join(enabled_region_labels)}\n")
        self.output.see(tk.END)

        # --- блок чекбоксов по платформам ---
        enabled_platform_labels = [label for label, var in self.platform_vars.items() if var.get()]
        enabled_platforms = []
        for label in enabled_platform_labels:
            enabled_platforms.extend(PLATFORM_GROUPS[label])
        # print(enabled_platforms)
        if not enabled_platforms:
            messagebox.showerror("Ошибка!", "Нужно выбрать хотя бы одну платформу!")
            self.all_platforms_var.set(False)
            return

        # выводим в лог
        self.output.insert(tk.END, f"Выбранные платформы: {', '.join(enabled_platform_labels)}\n\n")
        self.output.see(tk.END)

        strict_mode = self.strict_var.get()

        self.search_btn.config(state=tk.DISABLED)
        self.clear_ip_btn.config(state=tk.DISABLED)
        # self.save_btn.config(state=tk.DISABLED)
        # self.delete_btn.config(state=tk.DISABLED)
        self.reverse_btn.config(state=tk.DISABLED)
        # self.help_btn.config(state=tk.DISABLED)
        # print(enabled_ues)
        def add_result(res):
            # src_or_dst_mode
            # if len(res) == 0: self.output.insert(tk.END, "Ничего не найдено.\n")
            buffer = ""
            cnt=0
            # found = False
            # print(Api_search3.main(loc))
            # print(res)
            try:
                for line in res:
                    # found = True
                    buffer += line + "\n"
                    cnt+=1
                    if cnt >= 10:
                        self.output.insert(tk.END, buffer)
                        self.output.see(tk.END)
                        # self.root.update()
                        buffer = ""
                        cnt=0
                if buffer:
                    self.output.insert(tk.END, buffer)
                    self.output.see(tk.END)
                # if not found:
                #     self.output.insert(tk.END, "Ничего не найдено для .\n\n")
                self.root.update()
            except:
                pass

        # 1234
        from itertools import chain as chir
        if strict_mode:
            addstrict = " в строгом соответствии"
        else: addstrict = ""

        def worker():

            if src_or_dst_mode:
                if src_ip!="any":
                    search_ip = src_ip
                    res = Api_search3.main(search_ip, "any", enabled_prefixes, enabled_platforms, enabled_ues, strict_mode)
                    first = next(res, None)
                    if first is None: self.output.insert(tk.END, f"Ничего не найдено{addstrict} для {search_ip} → any\n\n")
                    else:  res = chir([first], res); add_result(res)
                    self.output.insert(tk.END, "--Обратный поиск--\n\n")
                    res = Api_search3.main("any", search_ip, enabled_prefixes, enabled_platforms, enabled_ues, strict_mode)
                    first = next(res, None)
                    if first is None: self.output.insert(tk.END, f"Ничего не найдено{addstrict}для any → {search_ip} \n\n")
                    else: res = chir([first], res); add_result(res)
                else:
                    search_ip = dst_ip
                    res = Api_search3.main("any", search_ip, enabled_prefixes, enabled_platforms, enabled_ues, strict_mode)
                    first = next(res, None)
                    if first is None: self.output.insert(tk.END, f"Ничего не найдено{addstrict} для any → {search_ip} \n\n")
                    else: res = chir([first], res); add_result(res)
                    self.output.insert(tk.END, "--Обратный поиск--\n\n")
                    res = Api_search3.main(search_ip, "any", enabled_prefixes, enabled_platforms, enabled_ues, strict_mode)
                    first = next(res, None)
                    if first is None: self.output.insert(tk.END, f"Ничего не найдено{addstrict} для {search_ip} → any\n\n")
                    else: res = chir([first], res); add_result(res)
            else:
                res = Api_search3.main(src_ip, dst_ip, enabled_prefixes, enabled_platforms, enabled_ues, strict_mode)
                first = next(res, None)
                if first is None: self.output.insert(tk.END, f"Ничего не найдено{addstrict} для {src_ip} → {dst_ip}\n\n")
                else:
                    res = chir([first], res);
                    add_result(res)
                    # res = Api_search3.main(src_ip, dst_ip, enabled_prefixes, enabled_platforms, enabled_ues,
                    #                        strict_mode)
                    # try:
                    #     first = next(res, None)
                    #     res = chir([first], res)
                    #     add_result(res)
                    # except: pass




            # if no res: self.output.insert(tk.END, "Ничего не найдено.\n")
            self.output.insert(tk.END, "✅ Поиск завершен.\n----\n")
            # self.output.insert(tk.END, "----\n")
            self.output.see(tk.END)
            # self.output.insert(tk.END, "----")
            self.search_btn.config(state=tk.NORMAL)
            self.clear_ip_btn.config(state = tk.NORMAL)
            # self.save_btn.config(state=tk.NORMAL)
            # self.delete_btn.config(state=tk.NORMAL)
            self.reverse_btn.config(state=tk.NORMAL)
            # self.help_btn.config(state=tk.NORMAL)
            self.output.config(state="disabled")


        threading.Thread(target=worker, daemon=True).start()
    # ---------------- DOWNLOAD WINDOW ----------------
    def open_download_window(self):

        win = tk.Toplevel(self.root)
        win.title("Скачивание конфигураций")
        win.configure(bg="#f0f0f0")
        win.geometry("600x800")  # фиксированный размер
        win.resizable(True, True)  # запрет изменения размера
        self.root.bind("<Escape>", lambda e: self.root.destroy())
        for widget in self.root.winfo_children():
            widget.destroy()

        win = tk.Frame(self.root, padx=10, pady=10,bg="#f0f0f0")
        win.pack(fill="both", expand=True)
        # 1000
        win.grid_rowconfigure(6, weight=1, minsize=300)
        # win.grid_columnconfigure(0, weight=1)
        win.grid_columnconfigure(1, weight=1, minsize=300)
        # win.grid_columnconfigure(0, weight=0)
        # win.grid_columnconfigure(1, weight=1)

        tk.Label(win, text="GitLab login:",bg="#f0f0f0").grid(row=0, column=0, sticky="e",padx=(0,5))
        login_entry = tk.Entry(win, width=30)
        login_entry.grid(row=0, column=1,sticky="nw", padx=5)
        fix_entry_shortcuts(login_entry)
        limit_entry_length(login_entry, 50)

        tk.Label(win, text="GitLab password:",bg="#f0f0f0").grid(row=1, column=0, sticky="e",padx=(0,5))
        pass_entry = tk.Entry(win, width=30, show="*")
        pass_entry.grid(row=1, column=1,sticky="nw", padx=5)
        fix_entry_shortcuts(pass_entry)
        limit_entry_length(pass_entry,64)

        tk.Label(win, text="NetBox API token:",bg="#f0f0f0").grid(row=2, column=0, sticky="e",padx=(0,5), pady=5)
        token_entry = tk.Entry(win, width=60, show="*")
        token_entry.grid(row=2, column=1,sticky="nw", padx=5)
        fix_entry_shortcuts(token_entry)
        limit_entry_length(token_entry,50)

        # чекбоксы для ЦОД/ЛВС
        lvs_var = tk.BooleanVar(value=False)
        dc_var = tk.BooleanVar(value=False)
        choise_frame = tk.Frame(win, bg="#f0f0f0", bd=0, highlightthickness=0)
        choise_frame.grid(row = 4, column = 0,columnspan=2, sticky = "")

        tk.Label(choise_frame, text="ЛВС:", bg="#f0f0f0").grid(row=0, column=0, sticky="e", padx=0)
        lvs_cb = tk.Checkbutton(
            choise_frame,
            variable=lvs_var,
            bg="#f0f0f0",
            activebackground="#f0f0f0",
            highlightthickness=0,
            bd=0,
            padx=-2,
            pady=0
        )
        lvs_cb.grid(row=0, column=1, sticky="w")

        tk.Label(choise_frame, text="ЦОД:", bg="#f0f0f0").grid(row=0, column=2, sticky="e", padx=(10,0))
        dc_cb = tk.Checkbutton(
            choise_frame,
            variable=dc_var,
            bg="#f0f0f0",
            activebackground="#f0f0f0",
            highlightthickness=0,
            bd=0,
            padx=-2,
            pady=0
        )
        dc_cb.grid(row=0, column=3, sticky="w")


        def download():
            log_area.config(state="normal")
            login = login_entry.get().strip()
            password = pass_entry.get().strip()
            token = token_entry.get().strip()
            lvs = lvs_var.get()
            dc = dc_var.get()

            if not login or not password or not token:
                messagebox.showerror("Ошибка", "Введите логин, пароль и токен!")
                return

            if not lvs and not dc:
                messagebox.showerror("Ошибка", "Выберите объект загрузки.")
                return

            box = [[dc, "ЦОД"],[lvs, "ЛВС"]]
            # print(box, "1")
            log_area.see(tk.END)

            download_btn.config(state=tk.DISABLED)
            lvs_cb.config(state=tk.DISABLED)
            dc_cb.config(state=tk.DISABLED)

            def add_log(line):
                def update_log():
                    log_area.insert(tk.END, line + "\n")
                    log_area.see(tk.END)
                    log_area.update_idletasks()  # Для плавности

                self.root.after(0, update_log)

            def on_success():
                def update_success():
                    messagebox.showinfo("Ура!", "Скачалось успешно!", parent=win)
                    win.destroy()
                    self.build_main_window()

                self.root.after(0, update_success)

            def on_failure(error_msg):
                def update_failure():
                    messagebox.showerror("Ошибка!", error_msg, parent=win)
                    # print(error_msg)
                    download_btn.config(state=tk.NORMAL)
                    log_area.config(state="disabled")

                self.root.after(0, update_failure)
            # print()
            def worker():
                try:
                    success = False
                    for line in copy_to_local_at_type.main(login, password, token, box):
                        add_log(line)
                        if line.startswith("\n👍 Все"):
                            time.sleep(0.5)
                            success = True
                    if success:
                        # time.sleep(1)  # Если нужно
                        on_success()
                    else:
                        on_failure("Скачивание не удалось!")
                except Exception as e:
                    # print(e)
                    add_log(f"❌ Ошибка: {e}")
                    on_failure("Скачивание не удалось!")

            threading.Thread(target=worker, daemon=True).start()



        choise_frame = tk.Frame(win, bg="#f0f0f0")
        choise_frame.grid(row=4, column=0, columnspan=2, pady=(10,10))

        frame1 = tk.Frame(choise_frame, bg="#f0f0f0")
        frame1.pack(side="left", padx=0,pady=(0,0))  # ← расстояние между блоками

        download_btn = tk.Button(win, text="Скачать", command=download)
        download_btn.grid(row=5, column=0, columnspan=2, pady=(5, 5))  # немного сверху и снизу

        # Frame под кнопкой
        # choise_frame = tk.Frame(win, bg="#f0f0f0")
        # choise_frame.grid(row=3, column=0, columnspan=2, pady=(0, 5))

        # чекбоксы внутри frame через grid

        # choise_frame = tk.LabelFrame(win, text="ЛВС:",bg="#f0f0f0")
        # choise_frame.grid(row = 4, column = 0, sticky = "nw")


        # print(ищч)
        # if not box[0][0] and not box[1][0]:
        #     messagebox.showerror("Ошибка", "Выберите объект загрузки.")
        #     return


        self.root.bind("<Control-Shift-f>", lambda event: download())
        self.root.bind("<Control-Shift-F>", lambda event: download())
        self.bind_enter_to_button(download_btn)

        log_area = scrolledtext.ScrolledText(win, wrap=tk.WORD,state="disabled",takefocus=0)
        # log_area.grid(row=5, column=0, columnspan=2, pady=10)
        log_area.grid(row=6, column=0, columnspan=2, sticky="nsew", pady=4)
        # win.grid_rowconfigure(5, weight=1)

if __name__ == "__main__":
    root = tk.Tk()
    app = ParserApp(root)
    root.mainloop()
