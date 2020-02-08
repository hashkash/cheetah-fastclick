#include <click/config.h>
#include <click/router.hh>
#include <click/args.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <click/flow/ctxelement.hh>


CLICK_DECLS

bool StackVisitor::visit(Element *e, bool, int port, Element*, int, int)
{
    // Check that the element is a stack element
    // If this is not the case, we skip it and continue the traversing
    if(!CTXElement::isCTXElement(e)) {
        //click_chatter("%p{element} is not stack",e);
        return true;
    }

    // We now know that we have a stack element so we can cast it
    CTXElement *element = reinterpret_cast<CTXElement*>(e);

    // Add the starting element in the list of the current element
    click_chatter("Adding element %p{element} as predecessor of %p{element}",
            startElement, element);
    element->addCTXElementInList(startElement, port);

    // Stop search when we encounter the IPOut Element
    if(strcmp(element->class_name(), "IPOut") == 0)
        return false;

    // Stop the traversing
    return false;
}

CTXElement::CTXElement()
{
    previousCTXElement = NULL;
}

CTXElement::~CTXElement()
{

}

bool CTXElement::isCTXElement(Element* element)
{
    if(element->cast("CTXElement") != NULL)
        return true;
    else
        return false;
}

void* CTXElement::cast(const char *name)
{
    if(strcmp(name, "CTXElement") == 0)
        return (CTXElement*)this;
    else
        return VirtualFlowSpaceElement::cast(name);
 }

void CTXElement::buildFunctionStack()
{
    StackVisitor visitor(this);
    this->router()->visit_downstream(this, -1, &visitor);
}

void CTXElement::addCTXElementInList(CTXElement *element, int port)
{
    // Check that this element has not already been added in the list via an
    // alternative path

    previousCTXElement = element;
}


void CTXElement::closeConnection(Packet *packet, bool graceful)
{
    // Call the "closeConnection" method on every element in the stack
    if(previousCTXElement == NULL)
        return;

    previousCTXElement->closeConnection(packet, graceful);
}

bool CTXElement::isEstablished()
{
    // Call the "closeConnection" method on every element in the stack
    if(previousCTXElement == NULL) {
        return false;
    }

    return previousCTXElement->isEstablished();
}


bool CTXElement::registerConnectionClose(StackReleaseChain* fcb_chain, SubFlowRealeaseFnt fnt, void* thunk)
{
    // Call the "closeConnection" method on every element in the stack
    if(previousCTXElement == NULL) {
        click_chatter("No previous stack in %p{element}", this);
        return false;
    }

    return previousCTXElement->registerConnectionClose(fcb_chain, fnt, thunk);
}

int CTXElement::maxModificationLevel(Element* stop) {
    assert(router()->handlers_ready());
    if(previousCTXElement == stop || previousCTXElement == 0)
        return 0;

    return previousCTXElement->maxModificationLevel(stop);
}
/*
void CTXElement::removeBytes(WritablePacket* packet, uint32_t position,
    uint32_t length)
{
    //click_chatter("Calling rmbyte on %p{element}", this);
    // Call the "removeBytes" method on every element in the stack
    if(previousCTXElement == NULL) {
        //click_chatter("No previous elem before %p{element}. Removing data",this);
        unsigned char *source = packet->data();
        position += packet->getContentOffset();
        uint32_t bytesAfter = packet->length() - position;
        if (bytesAfter > 0) {
            memmove(&source[position], &source[position + length], bytesAfter);
        }
        packet->take(length);
        return;
    }// else
        //click_chatter("Previous elem before %p{element} that is %p{element}",this,previousCTXElement);
    previousCTXElement->removeBytes(packet, position, length);
}

WritablePacket* CTXElement::insertBytes(WritablePacket* packet,
    uint32_t position, uint32_t length)
{
    // Call the "insertBytes" method on every element in the stack
    if(previousCTXElement == NULL) {
        uint32_t bytesAfter = packet->length() - position;
//        click_chatter("bytes after %d, position %d, put %d", bytesAfter, position, length);
        WritablePacket *newPacket = packet->put(length);
        assert(newPacket != NULL);
        unsigned char *source = newPacket->data();
        if (bytesAfter > 0)
            memmove(&source[position + length], &source[position], bytesAfter);
        return newPacket;
    }

    return previousCTXElement->insertBytes(packet, position, length);
}

void CTXElement::requestMorePackets(Packet *packet, bool force)
{
    //click_chatter("%p{element} : requestMorePackets", previousCTXElement);

    // Call the "requestMorePackets" method on every element in the stack
    if(previousCTXElement == NULL)
        return;

    previousCTXElement->requestMorePackets(packet, force);
}

bool CTXElement::isLastUsefulPacket(Packet *packet)
{
    // Call the "isLastUsefulPacket" method on every element in the stack
    if(previousCTXElement == NULL)
        return false;

    return previousCTXElement->isLastUsefulPacket(packet);
}


unsigned int CTXElement::determineFlowDirection()
{
    // Call the "determineFlowDirection" method on every element in the stack
    if(previousCTXElement == NULL)
        return -1; // We've reached the end of the path and nobody answered

    return previousCTXElement->determineFlowDirection();
}
*/
CLICK_ENDDECLS
EXPORT_ELEMENT(CTXElement)
//ELEMENT_MT_SAFE(CTXElement)
