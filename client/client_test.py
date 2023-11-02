from smartcard.CardType import AnyCardType

from smartcard.CardRequest import CardRequest

from smartcard.util import toHexString

cardtype = AnyCardType()

cardrequest = CardRequest( timeout=1, cardType=cardtype )

cardservice = cardrequest.waitforcard()

cardservice.connection.connect()

print(toHexString(cardservice.connection.getATR()))

print(cardservice.connection.getReader())
