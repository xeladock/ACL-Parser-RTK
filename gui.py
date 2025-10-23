import ipaddress
import time
import os
import threading
from re import sub as rs
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import Api_search3, copy_to_local_at_type
from datetime import datetime
import shutil

CONFIG_DIR = "collected_files_clear"

PREFIX_LABELS = {
    "Волга": "PRNG-DC",
    "ДВ": "DVPR-DC",
    "СЗ": "SZSP-DC",
    "Центр": "CEMO-DC",
    "КЦ": "CEMS-DC",
    "Урал": "UREK-DC",
    "Юг": "UKFR-DC",
    "Сибирь": "SINO-DC",
}


PLATFORM_GROUPS = {
    "Cisco ASA": ["Cisco ASA"],
    "Cisco Firepower": ["Cisco FXOS"],
    "Cisco IOS": ["Cisco IOS"],
    "Cisco IOS XE": ["Cisco IOS XE"],
    "Cisco NX-OS": ["Cisco NX-OS"],
    "FortiOS": ["FortiOS"],
    "Huawei": ["Huawei VRP"],
    "Прочие устройства": [   # всё остальное
        "B4COM BCOM-OS-DC", "EdgeCore", "IBM_Lenovo Network OS",
        "HP ProCurve", "Dell Networking OS", "Juniper Junos", "Eltex", "Cisco IOS XR", "Cisco PIX"
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


class ParserApp:
    # LIGHT_BG = "#f0f0f0"
    def __init__(self, root):
        self.all_regions_var = None
        self.root = root
        self.root.title("ACL Parser. Версия для AltLinux.")
        self.root.geometry("1100x820")
        self.root.configure(bg="#f0f0f0")
        self.root.resizable(False, False)
        if not os.path.exists(CONFIG_DIR) or not os.listdir(CONFIG_DIR):
            self.open_download_window()
        else:
            self.build_main_window()

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


        # формируем имя файла: src-dst-dd-mm-yyyy-hh-mm.txt
        timestamp = datetime.now().strftime("%d-%m-%Y-%H-%M")
        filename = f"{src_ip}-{dst_ip}-{timestamp}.txt"

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
        filename = f"{src_ip}-{dst_ip}-{now}.txt"

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
    def build_main_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        # Отключаем растяжение для всего окна

        self.root.grid_columnconfigure(2, weight=0)

        self.root.grid_rowconfigure(2, weight=0)

        # Создаем фрейм и прижимаем его к левому верхнему углу
        frame = tk.Frame(self.root,bg="#f0f0f0")
        frame.grid(row=0, column=0, sticky="nw", padx=5, pady=5)

        # Отключаем растяжение внутри фрейма
        # frame.grid_columnconfigure(0, weight=0)
        frame.grid_columnconfigure(2, weight=2)
        # frame.grid_rowconfigure(0, weight=0)
        frame.grid_rowconfigure(2, weight=0)

        # Создаем отдельный фрейм для полей ввода, чтобы лучше контролировать их выравнивание
        input_frame = tk.Frame(frame,bg="#f0f0f0")
        input_frame.grid(row=0, column=0, sticky="nw", padx=5, pady=9)  # 🔹 Новый фрейм, прижатый влево

        # Поля ввода
        tk.Label(input_frame, text="Source IP:",bg="#f0f0f0").grid(row=0, column=0, sticky="w", padx=(10, 5))  #  sticky="w" вместо "e"
        self.src_entry = tk.Entry(input_frame, width=30)
        self.src_entry.grid(row=0, column=1, sticky="nw", padx=5)  # 🔹 Убедимся, что поле прижато влево
        # self.src_entry.bind("<Control-a>", select_all)
        # self.src_entry.bind("<Control-A>", select_all)
        fix_entry_shortcuts(self.src_entry)
        limit_entry_length(self.src_entry, 50)
        add_placeholder(self.src_entry, "any", "gray")

        tk.Label(input_frame, text="Destination IP:",bg="#f0f0f0").grid(row=1, column=0, sticky="w", padx=(10, 5))  # 🔹 sticky="w" вместо "e"
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
        self.reverse_btn.grid(row=2, column=0, columnspan=2, pady=(2, 0), padx=(270, 0))
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

        # tk.LabelFrame(frame, text="Фильтр по префиксам файлов:")
        prefix_frame = tk.LabelFrame(frame, text="Фильтр по регионам:",bg="#f0f0f0")
        prefix_frame.grid(row = 0, column = 1, sticky = "nw", padx = 10)

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
        platform_frame.grid(row=0, column=1, sticky="nw",padx=320)

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
        self.search_btn = tk.Button(frame, text="Поиск", command=self.run_search)
        self.search_btn.grid(row=4, column=0, columnspan=2, pady=10,sticky="w", padx=500)

        self.root.bind("<Control-Shift-f>", lambda event: self.run_search())
        self.root.bind("<Control-Shift-F>", lambda event: self.run_search())
        self.bind_enter_to_button(self.search_btn)

        # Окно вывода
        self.output = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=133, height=31.1,state="disabled")
        self.output.grid(row=5, column=0, columnspan=2, sticky="w", padx=5)
        self.save_btn = tk.Button(frame, text="Сохранить на диск", command=self.save_output)
        self.save_btn.grid(row=6, column=0, columnspan=2, padx=6,pady=(5,0), sticky="w")
        self.delete_btn = tk.Button(frame, text="Удалить папку конфигураций",
                                    command=self.delete_config_folder)
        self.delete_btn.grid(row=6, column=1, columnspan=2,padx=470, pady=(5, 0), sticky="w")

        self.root.bind("<Control-Shift-s>", lambda event: self.save_output())
        self.root.bind("<Control-Shift-S>", lambda event: self.save_output())
        self.root.bind("<Control-Shift-d>", lambda event: self.delete_config_folder())
        self.root.bind("<Control-Shift-D>", lambda event: self.delete_config_folder())
        self.root.bind("<Control-Shift-r>", lambda event: self.reverse_ips())
        self.root.bind("<Control-Shift-R>", lambda event: self.reverse_ips())

        self.root.bind("<Control-Shift-q>", self.quick_save_output)
        self.root.bind("<Control-Shift-Q>", self.quick_save_output)

        self.bind_enter_to_button(self.reverse_btn)
        self.bind_enter_to_button(self.save_btn)
        self.bind_enter_to_button(self.delete_btn)

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

        if src_or_dst_mode and ((src_ip!="any" and dst_ip!="any") or (src_ip=="any" and dst_ip=="any")):
            messagebox.showerror("Ошибка!",
                                 f"Должен быть один адрес в поле Source ИЛИ Destination.")
            return

        # self.output.config(state="normal")

        self.output.config(state="normal")

        # Собираем выбранные префиксы

        # --- блок чекбоксов по регионам ---
        enabled_region_labels = [label for label, var in self.prefix_vars.items() if var.get()]
        enabled_prefixes = [PREFIX_LABELS[label] for label in enabled_region_labels]

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

        # self.output.insert(tk.END, f"Запуск поиска ACL для {src_ip} → {dst_ip}\n\n")
        self.output.insert(tk.END, f"Активные регионы: {', '.join(enabled_region_labels)}\n")
        self.output.see(tk.END)

        # --- блок чекбоксов по платформам ---
        enabled_platform_labels = [label for label, var in self.platform_vars.items() if var.get()]
        enabled_platforms = []
        for label in enabled_platform_labels:
            enabled_platforms.extend(PLATFORM_GROUPS[label])

        if not enabled_platforms:
            messagebox.showerror("Ошибка!", "Нужно выбрать хотя бы одну платформу!")
            self.all_platforms_var.set(False)
            return

        # выводим в лог
        self.output.insert(tk.END, f"Активные платформы: {', '.join(enabled_platform_labels)}\n\n")
        self.output.see(tk.END)

        strict_mode = self.strict_var.get()

        self.search_btn.config(state=tk.DISABLED)
        self.save_btn.config(state=tk.DISABLED)
        self.delete_btn.config(state=tk.DISABLED)
        self.reverse_btn.config(state=tk.DISABLED)

        def add_result(res):
            buffer = ""
            cnt=0
            for line in res:
                buffer += line + "\n"
                cnt+=1
                if cnt > 10:
                    self.output.insert(tk.END, buffer)
                    self.output.see(tk.END)
                    # self.root.update()
                    buffer = ""
                    cnt=0
            if buffer:
                self.output.insert(tk.END, buffer)
                self.output.see(tk.END)
            self.root.update()

        def worker():
            if src_or_dst_mode:
                if src_ip!="any":
                    search_ip = src_ip
                # else:             search_ip = dst_ip
                    res = Api_search3.main(search_ip, "any", enabled_prefixes, enabled_platforms, strict_mode)
                    add_result(res)
                    self.output.insert(tk.END, "--Обратный поиск--\n\n")
                    # self.output.see(tk.END)
                    res = Api_search3.main("any", search_ip, enabled_prefixes, enabled_platforms, strict_mode)
                    add_result(res)
                else:
                    search_ip = dst_ip
                    # else:             search_ip = dst_ip
                    res = Api_search3.main("any", search_ip, enabled_prefixes, enabled_platforms, strict_mode)
                    add_result(res)
                    # self.output.see(tk.END)
                    self.output.insert(tk.END, "--Обратный поиск--\n\n")
                    res = Api_search3.main(search_ip, "any", enabled_prefixes, enabled_platforms, strict_mode)
                    add_result(res)
            else:
                res = Api_search3.main(src_ip, dst_ip, enabled_prefixes, enabled_platforms, strict_mode)
            add_result(res)
            self.output.insert(tk.END, "✅ Поиск завершен.\n")
            self.search_btn.config(state=tk.NORMAL)
            self.save_btn.config(state=tk.NORMAL)
            self.delete_btn.config(state=tk.NORMAL)
            self.reverse_btn.config(state=tk.NORMAL)
            self.output.config(state="disabled")


        threading.Thread(target=worker, daemon=True).start()
    # ---------------- DOWNLOAD WINDOW ----------------
    def open_download_window(self):

        win = tk.Toplevel(self.root)
        win.title("Скачивание конфигураций")
        win.configure(bg="#f0f0f0")
        win.geometry("600x800")  # фиксированный размер
        win.resizable(False, False)  # запрет изменения размера
        for widget in self.root.winfo_children():
            widget.destroy()

        win = tk.Frame(self.root, padx=10, pady=10,bg="#f0f0f0")
        win.pack(fill="both", expand=True)

        win.grid_columnconfigure(0, weight=0)
        win.grid_columnconfigure(1, weight=1)

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

        tk.Label(win, text="NetBox API token:",bg="#f0f0f0").grid(row=2, column=0, sticky="e",padx=(0,5))
        token_entry = tk.Entry(win, width=60, show="*")
        token_entry.grid(row=2, column=1,sticky="nw", padx=5)
        fix_entry_shortcuts(token_entry)
        limit_entry_length(token_entry,50)

        log_area = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=135, height=35,state="disabled")
        log_area.grid(row=4, column=0, columnspan=2, pady=10)

        def download():
            log_area.config(state="normal")
            login = login_entry.get().strip()
            password = pass_entry.get().strip()
            token = token_entry.get().strip()

            if not login or not password or not token:
                messagebox.showerror("Ошибка", "Введите логин, пароль и токен!")
                return

            log_area.see(tk.END)
            download_btn.config(state=tk.DISABLED)

            def add_log(line):
                def update_log():
                    log_area.insert(tk.END, line + "\n")
                    log_area.see(tk.END)
                    log_area.update_idletasks()  # Для плавности

                self.root.after(0, update_log)

            def on_success():
                def update_success():
                    messagebox.showinfo("Успех!", "Скачалось успешно!", parent=win)
                    win.destroy()
                    self.build_main_window()

                self.root.after(0, update_success)

            def on_failure(error_msg):
                def update_failure():
                    messagebox.showerror("Ошибка!", error_msg, parent=win)
                    download_btn.config(state=tk.NORMAL)

                self.root.after(0, update_failure)

            def worker():
                try:
                    success = False
                    for line in copy_to_local_at_type.main(login, password, token):
                        add_log(line)
                        if  line.startswith("✅ Все файлы"):
                            success = True
                    if success:
                        time.sleep(1)  # Если нужно
                        on_success()
                    else:
                        on_failure("Скачивание не удалось!")
                except Exception as e:
                    add_log(f"❌ Ошибка: {e}")
                    on_failure("Скачивание не удалось!")

            threading.Thread(target=worker, daemon=True).start()
        download_btn = tk.Button(win, text="Скачать", command=download)
        download_btn.grid(row=3, column=0, columnspan=2, pady=(13, 0))

if __name__ == "__main__":
    root = tk.Tk()
    app = ParserApp(root)
    root.mainloop()
