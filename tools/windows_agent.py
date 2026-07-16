import requests
import time
import uuid


API_URL = (
    "http://127.0.0.1:8000"
    "/api/v1/windows-events"
)



def send_event(
    event_id,
    username,
    source_ip
):

    xml = f"""
<Event>
<System>

<EventID>
{event_id}
</EventID>

<Computer>
WORKSTATION-01
</Computer>

<Provider>
Microsoft-Windows-Security-Auditing
</Provider>

</System>


<EventData>

<Data Name="TargetUserName">
{username}
</Data>


<Data Name="IpAddress">
{source_ip}
</Data>


</EventData>

</Event>
"""


    payload = {

        "record_id":
            int(uuid.uuid4().int % 1000000),


        "event_id":
            event_id,


        "computer":
            "WORKSTATION-01",


        "provider":
            "Microsoft-Windows-Security-Auditing",


        "source_ip":
            source_ip,


        "xml":
            xml

    }



    response = requests.post(
        API_URL,
        json=payload
    )


    print("STATUS:", response.status_code)

    print("CONTENT:")
    print(response.text)





if __name__ == "__main__":


    print(
        "Sending Windows events..."
    )


    # successful login

    send_event(

        event_id=4624,

        username="alice",

        source_ip="192.168.1.20"

    )


    time.sleep(2)



    # failed login burst

    for i in range(5):

        send_event(

            event_id=4625,

            username="alice",

            source_ip="10.10.10.50"

        )


        time.sleep(1)