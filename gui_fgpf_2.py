import tkinter as tk
from tkinter import scrolledtext
from get_itog import get_systems_by_subnets
import ipaddress
import threading
has_run = False
search_done = {'value': False}
stop_event = threading.Event()
timer = None
timed_out = False
def run_pap(parent=None):

    def is_valid_subnet(s):
        try:
            ipaddress.IPv4Network(s.strip(), strict=False)
            return True
        except:
            return False

    def cnt(token):
        global timed_out
        raw_lines = input_field.get("1.0", tk.END).strip().splitlines()
        subnets = []
        # print(raw_lines)
        for line in raw_lines:
            stripped = line.strip()
            if not stripped:
                continue
            if is_valid_subnet(stripped):
                subnets.append(stripped)


        subnets = input_field.get("1.0", tk.END).strip().splitlines()
        subnets = [s.strip() for s in subnets if is_valid_subnet(s)]
        # print(subnets)
        active_threads = []
        output_written = {'value': False}  # был ли выведен хоть один результат

        # Шаг 1 — подготовка поля вывода
        output_field.config(state='normal')
        output_field.delete("1.0", tk.END)
        output_field.insert(tk.END, "🔄 Запрос выполняется. Пожалуйста, подождите...\n")
        output_field.config(state='disabled')
        calculate_button.config(state='disabled')
        # Шаг 2 — функция обновления результатов
        def insert_to_output(text):
            output_field.config(state='normal')

            # Удаляем последнюю строку "🔄 ..." перед вставкой нового результата
            content = output_field.get("1.0", tk.END)
            lines = content.strip().splitlines()

            if lines and lines[-1].startswith("🔄"):
                lines = lines[:-1]  # удалить "🔄 ..."

            # Вставляем результат + снова "🔄 ..."
            lines.append(text)
            lines.append("🔄 Запрос выполняется. Пожалуйста, подождите...")

            output_field.delete("1.0", tk.END)
            output_field.insert("1.0", "\n".join(lines) + "\n")
            output_field.see(tk.END)
            output_field.config(state='disabled')

            output_written['value'] = True

        # Шаг 3 — обработка одной подсети
        def process_single_subnet(subnet):
            if stop_event.is_set():
                return
            try:
                systems, log = get_systems_by_subnets([subnet], token)
                if stop_event.is_set():  # проверяем ещё раз после долгого вызова
                    return
                if log:
                    result_text = f"▶ {subnet}\n" + "\n".join(log) + "\n"
                    output_field.after(0, insert_to_output, result_text)
            except Exception as e:
                # print()
                output_field.after(0, insert_to_output, f"⚠️ [{subnet}] ошибка: {e}")

        # Шаг 4 — запуск потоков
        for subnet in subnets:
            if stop_event.is_set():
                break
            t = threading.Thread(target=process_single_subnet, args=(subnet,),daemon=True)
            t.start()
            active_threads.append(t)

        # Шаг 5 — завершение
        def on_complete():
            for t in active_threads:
                if stop_event.is_set():
                    break
                t.join()

            def finish_message():
                global timed_out
                if timed_out:  # ← Главная проверка
                    return
                output_field.config(state='normal')
                # Удалим последнюю "ожидалку"
                content = output_field.get("1.0", tk.END)
                lines = content.strip().splitlines()

                if lines and lines[-1].startswith("🔄 Запрос"):
                    lines = lines[:-1]

                if not output_written['value']:
                    if not token:
                        lines = ["Нет токена.\n"]
                    if token:
                        lines = ["Наименований не найдено.\n"]
                    timer.cancel()
                if token:
                    lines.append("✅ Поиск в СТУ завершён.")

                output_field.delete("1.0", tk.END)
                output_field.insert("1.0", "\n".join(lines) + "\n")
                output_field.see(tk.END)
                output_field.config(state='disabled')

                input_field.config(state='disabled')
                calculate_button.config(text="Сброс",state='normal')
                # calculate_button.config(disa)
                global has_run
                has_run = True
                # print("has_run is", has_run)
                # print("timer is", timer)
                if timer is not None:
                    timer.cancel()

            output_field.after(0, finish_message)

        threading.Thread(target=on_complete).start()

    # Состояние: рассчитывали ли уже?

    PLACEHOLDER = "Вставьте сюда список подсетей/адресов"
    def clear_placeholder(event=None):
        if input_field.get("1.0", "end-1c").strip() == PLACEHOLDER:
            input_field.delete("1.0", tk.END)
            input_field.config(fg='black', font=('Arial', 10, 'normal'))

    def write_to_output(text, tag=None):
        output_field.config(state='normal')
        output_field.delete("1.0", tk.END)
        if tag:
            output_field.insert(tk.END, text, tag)
        else:
            output_field.config("italic", font=('Arial', 10, 'italic'))
            output_field.insert(tk.END, text)
            output_field.config(state='disabled')

    def is_token_ascii(token):
        try:
            token.encode('latin-1')
            return True
        except UnicodeEncodeError:
            return False

    def process_input():
        global has_run, timer,timed_out
        timed_out = False
        token = token_entry.get().strip()
        # Если уже рассчитывали — значит нажали "Сброс"
        if has_run:
            # Очистить всё и вернуть в исходное состояние
            input_field.config(state='normal')
            # input_field.delete("1.0", tk.END)

            output_field.config(state='normal')
            output_field.delete("1.0", tk.END)
            output_field.config(state='disabled')

            calculate_button.config(text="Поиск")
            has_run = False
            stop_event.clear()
            if timer is not None:
                timer.cancel()
            return

        input_text = input_field.get("1.0", tk.END).strip()
        # print("has_run2 is", has_run)
        # print("input_text is", input_text)
        if not input_text or input_text == PLACEHOLDER or not is_token_ascii(token):
            # global timer
            stop_event.clear()
            # timer.cancel()
            output_field.config(state='normal')  # разблокировать поле
            output_field.delete("1.0", tk.END)  # очистить
            output_field.insert(tk.END, "Токен и/или данные отсутствуют/неверны.\nДобавьте/исправьте информацию.")
            # 111
            # calculate_button.config(text="Сброс", state='normal')
            output_field.config(state='disabled')  # заблокировать снова
            return
        else:
            calculate_button.config(state='disabled')
            write_to_output("⏳ Запрос выполняется. Пожалуйста, подождите...\n", tag="italic") # write_to_output("🔄 Запрос выполняется, пожалуйста подождите...\n", tag="italic")
            thread = threading.Thread(target=cnt, args=(token,),daemon=True)
            thread.start()
        # print("input_text2 is", input_text)
        def timeout_check():
            global timed_out, timer
            if timed_out:
                return
            timed_out = True
            stop_event.set()

            # if not search_done['value'] or not input_text or input_text == PLACEHOLDER:
            #     stop_event.set() # сигнал потокам, что надо завершиться
            #     print("код прошёл")
            #     timer.cancel()

            if output_field.winfo_exists():
                print("output_place is",output_field.winfo_exists())
                output_field.config(state='normal')
                # output_field.delete("1.0", tk.END)
                output_field.insert(tk.END, "⛔ Программа остановлена, т.к. выполняется слишком долго (более минуты). Измените количество искомых объектов.")
                calculate_button.config(state="normal")
                # timer.cancel()
                # stop_event.set()
                output_field.config(state='disabled')
            if timer is not None:
                    timer.cancel()
                # stop_event.set()
                # timer.cancel()


            # if timer is not None:
            #     timer.cancel()

        timer = threading.Timer(60, timeout_check)
        timer.daemon = True
        timer.start()

    ###
    ###
        if input_text == PLACEHOLDER:
            input_field.delete("1.0", tk.END)
            input_field.config(fg='black', font=('Arial', 10, 'normal'))
        input_field.config(state='disabled')
        calculate_button.config(text="Сброс",state='normal')
        # if timer is not None:
        #     timer.cancel()
        # stop_event.set()
        # timer.cancel()


        has_run = True

    # Главное окно
    root = tk.Toplevel(parent)
    # root = tk.Tk()
    root.title("Поиск наименований систем в СТУ Netbox.rt.ru")
    root.geometry("800x700")
    root.resizable(False, False)
    root.configure(bg="#f0f0f0")

    root.bind("<Shift-F2>", lambda e: run_pap())
    root.bind("<Escape>", lambda e: root.destroy())

    def toggle_token_visibility():
        if show_token_var.get():
            token_entry.config(show="")  # показываем как обычный текст
        else:
            token_entry.config(show="*")  # скрываем как пароль

    def focus_next(event):
        event.widget.tk_focusNext().focus()
        return "break"  # отменяет стандартное поведение Tab

    #
    # def on_close():
    #     stop_event.set()   # сигнал потокам завершиться
    #     root.destroy()     # закрыть окно

    # Поле токена

    def select_all_token(event):
        token_entry.select_range(0, tk.END)
        token_entry.icursor(tk.END)
        return 'break'

    def select_all_input(event):
        input_field.tag_add('sel', '1.0', tk.END)  # Выделяем текст от начала до конца
        input_field.mark_set(tk.INSERT, tk.END)    # Устанавливаем курсор в конец
        return 'break'

    def select_all_output(event):
        output_field.tag_add('sel', '1.0', tk.END)  # Выделяем текст от начала до конца
        output_field.mark_set(tk.INSERT, tk.END)    # Устанавливаем курсор в конец
        return 'break'

    def paste_to_input(event):
        try:
            # Если есть выделенный текст, удаляем его
            if input_field.tag_ranges('sel'):
                input_field.delete('sel.first', 'sel.last')
            # Вставляем текст из буфера обмена
            input_field.insert(tk.INSERT, root.clipboard_get())
        except tk.TclError:
            pass
        return 'break'

    def paste_from_clipboard(event):
        try:
            # Если есть выделенный текст, удаляем его
            if token_entry.selection_present():
                token_entry.delete('sel.first', 'sel.last')
            # Вставляем текст из буфера обмена
            token_entry.insert(tk.INSERT, root.clipboard_get())
        except tk.TclError:
            pass
        return 'break'

    tk.Label(root, text="API Token NetBox:",bg="#f0f0f0").pack(anchor='w', padx=10, pady=(10, 0))
    token_entry = tk.Entry(root, width=70, show="*")  # ← скрытый токен (как пароль)
    token_entry.pack(padx=10, pady=(0, 10))
    token_entry.bind('<Control-a>', select_all_token)
    token_entry.bind('<Control-A>', select_all_token)
    token_entry.bind('<Control-v>', paste_from_clipboard)   # английская V
    token_entry.bind('<Control-V>', paste_from_clipboard)
    # token_entry.bind('<Control-ц>', paste_from_clipboard)   # русская ц
    # token_entry.bind('<Control-Ц>', paste_from_clipboard)

    show_token_var = tk.BooleanVar(value=False)

    show_token_checkbox = tk.Checkbutton(
        root,
        bg="#f0f0f0",
        text="Показать токен",
        variable=show_token_var,
        command=toggle_token_visibility,
        activebackground="#f0f0f0",
        highlightthickness=0,  # убираем рамку фокуса
        bd=0,
        font=('Arial', 10, 'bold')
    )


    show_token_checkbox.pack(anchor='w', padx=10)


    # Поле ввода
    tk.Label(root, text="Ввод:",bg="#f0f0f0").pack(anchor='w', padx=10, pady=(10, 0))
    input_field = scrolledtext.ScrolledText(root, width=90, height=10)
    input_field.pack(padx=10, pady=(0, 10))
    input_field.insert("1.0", PLACEHOLDER)
    input_field.config(fg='gray', font=('Arial', 10, 'italic'))
    input_field.bind("<FocusIn>", clear_placeholder)
    input_field.bind("<Tab>", focus_next)
    input_field.bind('<KP_Enter>', lambda event: input_field.event_generate('<Return>'))
    input_field.bind('<Control-a>', select_all_input)
    input_field.bind('<Control-A>', select_all_input)
    input_field.bind('<Control-v>', paste_to_input)
    input_field.bind('<Control-V>', paste_to_input)


    # Кнопка "Рассчитать"
    calculate_button = tk.Button(root, text="Поиск", font=('Arial', 10, 'bold'), bg="#e0e0e0", command=process_input, takefocus=1)
    # calculate_button.place(relx=0.5, rely=0.5, anchor='center')
    calculate_button.pack(pady=0)
    calculate_button.bind('<Control-s>', lambda event: process_input())
    calculate_button.bind('<Control-S>', lambda event: process_input())

    # root.bind('<Return>', lambda event: calculate_button.invoke())
    # Поле вывода (только для чтения)
    tk.Label(root, text="Вывод:",bg="#f0f0f0").pack(anchor='w', padx=10, pady=0)
    output_field = scrolledtext.ScrolledText(root, width=110, height=20, wrap="word", state='disabled')
    output_field.pack(padx=10, pady=(0, 10))
    output_field.bind('<Control-a>', select_all_output)
    output_field.bind('<Control-A>', select_all_output)

# Запуск GUI
# root.bind('<Return>', lambda event: process_input())

# root.protocol("WM_DELETE_WINDOW", on_close)
