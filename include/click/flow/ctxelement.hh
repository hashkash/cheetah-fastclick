#ifndef MIDDLEBOX_STACKELEMENT_HH
#define MIDDLEBOX_STACKELEMENT_HH
#include <click/config.h>
#include <click/element.hh>
#include <click/router.hh>
#include <click/routervisitor.hh>
#include <click/flow/flowelement.hh>

CLICK_DECLS


struct StackReleaseChain {
    SubFlowRealeaseFnt previous_fnt;
    void* previous_thunk;
};

/*
=c

CTXElement()

=s middlebox

base class for the stack of the middlebox

=d

This element provides a common abstract base for the elements of the stack of the middlebox.
It provides useful methods and the mechanism of function stack. This element is not meant to be used
directly in a click configuration. Instead, use elements that inherit from it.

To use the function stack, simply call one of the methods using this mechanism and the method
will be called automatically on upstream elements until an IPIn element is reached. For instance,
to remove bytes in a packet, elements can simply call removeBytes, giving it the right parameters
and the method will be called on upstream elements that will handle the request and act
consequently.

Elements that inherit from this class can override the processPacket method to define their own
behaviour.

*/

class CTXElement : public VirtualFlowSpaceElement
{
public:

    /**
     * @brief Construct a CTXElement
     * CTXElement must not be instanciated directly. Consider it as an abstract element.
     */
    CTXElement() CLICK_COLD;

    /**
     * @brief Destruct a CTXElement
     */
    ~CTXElement() CLICK_COLD;

    // Click related methods
    const char *class_name() const        { return "CTXElement"; }
    const char *port_count() const        { return PORTS_1_1; }
    const char *processing() const        { return "h/hh"; }
    virtual const size_t flow_data_size() const { return 0; };
    void* cast(const char*);

    // Custom methods

    /**
     * @brief Method used during the building of the function stack. It sets the element
     * on which we must call the corresponding method to propagate the call in the stack
     * @param element The next element (upstream) in the function stack
     * @param port The input port connected to this element
     */
    virtual void addCTXElementInList(CTXElement* element, int port);

    /**
     * @brief Indicate whether an element is a stack element (which inherits from CTXElement)
     * @param element The element to check
     * @return A boolean indicating whether an element is a stack element
     */
    static bool isCTXElement(Element* element);

    /**
     * @brief Tells the maximum level of modification up to this element.
     * E.g tell if removeBytes and insertBytes are allowed by the current stack
     */
    virtual int maxModificationLevel(Element* stop);


protected:


    /**
     * @brief Used to create the function stack. It will run a StackVisitor
     * downstream that will register this element as the next element in the function stack
     * of the next stack element.
     */
    void buildFunctionStack();

    // Methods using the function stack mechanism

    const int MODIFICATION_NONE = 0;
    const int MODIFICATION_WRITABLE = 1; //May write to the packet without resizing
    const int MODIFICATION_STALL = 2;    //May stall packets
    const int MODIFICATION_REPLACE = 4;  //May replace some content
    const int MODIFICATION_RESIZE = 8;   //May resize the packet

    /**
     * @brief Remove bytes in a packet
     * @param fcb A pointer to the FCB of the flow
     * @param packet The packet
     * @param position The position (relative to the current useful content)
     * @param length Number of bytes to remove
     */
    //virtual void removeBytes(WritablePacket* packet, uint32_t position,
      //  uint32_t length);

    /**
     * @brief Insert bytes in a packet. This method creates room for the new bytes and moves
     * the content after the insertion point so that it is after the new bytes.
     * @param fcb A pointer to the FCB of the flow
     * @param packet The packet
     * @param position The position (relative to the current useful content)
     * @param length Number of bytes to insert
     * @return A pointer to the packet with the bytes inserted (can be different from the given
     * pointer)
     */
    //virtual WritablePacket* insertBytes(WritablePacket* packet, uint32_t position,
      //  uint32_t length) CLICK_WARN_UNUSED_RESULT;

    /**
     * @brief Request more packets. Must be used by objects that buffer packets to ensure that
     * they will receive the next packets
     * @param fcb A pointer to the FCB of the flow
     * @param packet The packet
     * @param force A boolean indicating whether the request must be repeated if it as already
     * been done for this packet (default: false)
     */
    //virtual void requestMorePackets(Packet *packet, bool force = false);

    /**
     * @brief Close the connection
     * @param fcb A pointer to the FCB of the flow
     * @param packet A packet from the connection, used for initialization
     * @param grafecul A boolean indicating whether the connection must be closed gracefully or not
     */
    virtual void closeConnection(Packet *packet, bool graceful);

    /**
     * @return true if event was handled
     */
    virtual bool registerConnectionClose(StackReleaseChain* fcb_chain, SubFlowRealeaseFnt fnt, void* thunk);

    /**
     * @brief Tells if the current session is established
     * Only applicable to context with connection status
     * @return A boolean indicating whether the connection is established or not
     * of the flow
     */
    virtual bool isEstablished();

    /**
     * @brief Indicate whether a given packet is the last useful one for this side of the flow
     * @param fcb A pointer to the FCB of the flow
     * @param packet The packet
     * @return A boolean indicating whether a given packet is the last useful one for this side
     * of the flow
     */
    //virtual bool isLastUsefulPacket(Packet *packet);

    /**
     * @brief Determine the flow ID for this path (0 or 1).
     * Each side of a TCP connection has a different flow direction (0 for one of them and 1
     * for the other).
     * This ID is defined in the Click configuration.
     * @return An unsigned int representing the ID (called direction) of the flow in the connection
     */
    //virtual unsigned int determineFlowDirection();

    virtual FlowControlBlock* get_opposite_fcb() = 0;

private:


    CTXElement *previousCTXElement; // Previous stack element in the configuration path
                                        // and therefore next element in the function stack.

};

template<typename T>
class CTXSpaceElement : public CTXElement {
public :
    CTXSpaceElement();

    ~CTXSpaceElement();


    virtual int initialize(ErrorHandler *errh) {
        CTXElement::initialize(errh);
        if (_flow_data_offset == -1) {
            return errh->error("No FlowClassifier() element sets the flow context for %s !",name().c_str());
        }
        return 0;
    }

    virtual const size_t flow_data_size()  const { return sizeof(T); }

    /**
     * Return the T type for a given FCB
     */
    inline T* fcb_data_for(FlowControlBlock* fcb) {
        T* flowdata = static_cast<T*>((void*)&fcb->data[_flow_data_offset]);
        return flowdata;
    }

    /**
     * Return the T type in the current FCB on the stack
     */
    inline T* fcb_data() {
        return fcb_data_for(fcb_stack);
    }

    void push_batch(int port,PacketBatch* head) final {
        //click_chatter("Pushing packet batch %p with fcb %p in %p{element}",head,fcb_data(),this);
        push_batch(port, fcb_data(), head);
    }

    virtual void push_batch(int port, T* flowdata, PacketBatch* head) = 0;

 };


/**
 * @brief This class defines a RouterVisitor that will be used to build the function stack
 * Each element starts a visitor downsteam so that when the visitor reaches the next CTXElement,
 * the object that started the visitor will be registered as the next element in the function stack
 * of the visited element.
 */
class StackVisitor : public RouterVisitor
{
public:
    /**
     * @brief Construct a StackVisitor
     */
    StackVisitor(CTXElement* startElement)
    {
        this->startElement = startElement;
    }

    /**
     * @brief Destruct a StackVisitor
     */
    ~StackVisitor()
    {

    }

    /**
     * @brief Visit the path of elements until we find a stack element. We will indicate to this
     * element that we are the next element in the function stack so that it will propagate
     * the calls to us. See the Click documentation for the description of the parameters
     */
    bool visit(Element *e, bool, int port, Element*, int, int);

private:
    CTXElement* startElement; // Element that started the visit
};

template<typename T>
CTXSpaceElement<T>::CTXSpaceElement() : CTXElement() {

}

template<typename T>
CTXSpaceElement<T>::~CTXSpaceElement() {

}


/**
 * CTXStateElement is like CTXSpaceElement but subscribe to the stack for connection open and close events
 *
 * The child must implement :
 * bool new_flow(T*, Packet*);
 * void push_batch(int port, T*, Packet*);
 * void release_flow(T*);
 *
 * This is the equivalent to FlowStateElement but use the last Stack element to
 * manage the state instead of relying on timeout/looking at the packet to learn
 * about a closing state
 */
template<class Derived, typename T> class CTXStateElement : public CTXElement {
    struct AT : public StackReleaseChain {
        T v;
        bool seen;
    };
public :


    CTXStateElement() CLICK_COLD {};
    virtual const size_t flow_data_size()  const { return sizeof(AT); }

    /**
     * CRTP virtual
     */
    inline bool new_flow(T*, Packet*) {
        return true;
    }

    /**
     * Return the T type for a given FCB
     */
    inline T* fcb_data_for(FlowControlBlock* fcb) {
        AT* flowdata = static_cast<AT*>((void*)&fcb->data[_flow_data_offset]);
        return &flowdata->v;
    }

    /**
     * Return the T type in the current FCB on the stack
     */
    inline T* fcb_data() {
        return fcb_data_for(fcb_stack);
    }

    static void release_fnt(FlowControlBlock* fcb, void* thunk ) {
        Derived* derived = static_cast<Derived*>(thunk);
        AT* my_fcb = reinterpret_cast<AT*>(&fcb->data[derived->_flow_data_offset]);
        derived->release_flow(&my_fcb->v);
        if (my_fcb->previous_fnt)
            my_fcb->previous_fnt(fcb, my_fcb->previous_thunk);
    }

    void push_batch(int port,PacketBatch* head) final {
         auto my_fcb = my_fcb_data();
         if (!my_fcb->seen) {
             if (static_cast<Derived*>(this)->new_flow(&my_fcb->v, head->first())) {
                 my_fcb->seen = true;
                 if (!this->registerConnectionClose(my_fcb, &release_fnt, (void*)this)) {
                     click_chatter("ERROR in %p{element}: No element handles the connection",this);
                     abort();
                 }
             } else {
                 head->fast_kill();
             }
         }
         static_cast<Derived*>(this)->push_batch(port, &my_fcb->v, head);
    };


private:
    inline AT* my_fcb_data() {
        return static_cast<AT*>((void*)&fcb_stack->data[_flow_data_offset]);
    }

};


CLICK_ENDDECLS

#endif
