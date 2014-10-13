import os
import glob
import yara
import pika

RULES_DIR = "rules/"
rules = ''

def on_message(channel, method_frame, header_frame, body):
    print "Got event type: ", method_frame.routing_key
    if method_frame.routing_key == "binarystore.file.added":
        file_info = json.loads(body)
        try:
            zf = zipfile.ZipFile(file_info["file_path"])
            bytes = zf.read("filedata")
            matches = rules.match(bytes)
            if matches:
                print "Found %d yara matches for %s: " % (file_info["file_path"], ",".join(matches))
        except Exception, err:
            print err

def get_rules(rules_dir):
    files = glob.glob(os.path.join(rules_dir, "*.yar"))
    filepaths = {}
    for f in files:
        filepaths[f] = f
    return yara.compile(filepaths=filepaths)

def setup_queue(user, passwd):
    # these are RabbitMQUser and RabbitMQPassword from /etc/cb/cb.conf
    credentials = pika.PlainCredentials(user, passwd)
    parameters = pika.ConnectionParameters('localhost', 5004, '/', credentials)
    connection = pika.BlockingConnection(parameters)
    channel = connection.channel()
    channel.queue_declare(queue='myqueue')
    channel.queue_bind(exchange='api.events', queue='myqueue', routing_key='#')
    channel.basic_consume(on_message, queue='myqueue')
    return (channel, connection)

if __name__ == "__main__":
    rules = get_rules(RULES_DIR)
    channel, connection = setup_queue("cb", "IGXYhLxtMV8z2sT0")
    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        channel.stop_consuming()
    connection.close()
