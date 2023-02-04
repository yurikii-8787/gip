# import the necessary files
from machine_app import *
from certificate_eds import Eds

def communication(client, server):
    print("Давайте теперь передовать сообщения между участниками. По типу: {отправитель} {сообщение} {конец связи?}")
    end = False
    while not end:
        print("                =============================                     ")
        from_m = input("Отправитель: ")
        message = input("Сообщение: ")
        end = input("Закончить сессию: [Yes/any word]: ")
        message_ = "Неверные входные данные"
        if end == "Yes": end = True
        else: end = False
        try:
            if from_m == client.key_file_name:
                message = client.encrypt_message(message)
                message_ = server.decrypt_message(message)
                print("Кодируем сообщение по символьно в: {}".format(message))
                print("Разкодируем сообщение по символьно в: {}".format(message_))
            elif from_m == server.key_file_name:
                message = server.encrypt_message(message)
                message_ = client.decrypt_message(message)
                print("Кодируем сообщение по символьно в: {}".format(message))
                print("Разкодируем сообщение по символьно в: {}".format(message_))
            else:
                print(message_)
        except Exception as e:
            print(e)



def main():
    server = Host(input("Выберите название сервера: "))
    client = Machine(input("Выберите название клиента: "))

    hello_message = "Who i wanna be..."
    if Eds(hello_message, client, server):
        print("Теперь клиент и сервер должны создать частичные ключи")
        server.generate_partial_key(client.public_key)
        client.generate_partial_key(server.public_key)
        print("Обмениваемся ключами и теперь клиент и сервер создали полные ключи, сравните их")
        server.co_partial_key, client.co_partial_key = client.my_partial_key, server.my_partial_key
        print("Теперь клиент и сервер создали полные ключи, сравните их: {} и {}".format(
            server.generate_master_key(),
            client.generate_master_key(server.public_key))
        )
        print("Это и есть мастер ключ, нужный для асиммитричного шифрования, теперь мы можем не пользоваться RSA и EDS")
        communication(client, server)
    else:
        print("Вмешивание в процесс, отключаю.")


if __name__ == '__main__':
    main()
