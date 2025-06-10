import ChatbotIcon from "./components/ChatbotIcon";
import ChatForm from "./components/ChatForm";
import ChatMessage from "./components/ChatMessage";
import React, { useEffect, useState, useRef } from "react";


const App = () => {
  const [chatHistory, setChatHistory] = useState([]);
  const [showChatbot, setShowChatbot] = useState(false);
  const chatBodyRef = useRef();

  const generateBotResponse = async (history) => {
  const updateHistory = (text, isError = false) => {
    setChatHistory(prev => [
      ...prev.filter(msg => msg.text !== "Thinking..."),
      { role: "model", text, isError }
    ]);
  };

  // Get the last user message
  const lastUserMessage = history.filter(msg => msg.role === "user").pop()?.text || "";
  // ZMIENIĆ JEŻELI CHCEMY ROBIĆ UPDATE ROUTERA
  const commit = false;
  const requestOptions = {
    method: "POST",
    headers: {
      "accept": "application/json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ text: lastUserMessage })
  };

  try {
    const response = await fetch(`http://localhost:8000/api/pfsense/?commit=${commit}`, requestOptions);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error?.message || "Something went wrong!");

    const apiResponseText = data.response || JSON.stringify(data); // Customize based on actual API response structure
    updateHistory(apiResponseText.trim());
  } catch (error) {
    updateHistory(error.message || "Failed to get a response.", true);
  }
};


  useEffect(() => {
    // Auto-scroll whenever chat history updates
    chatBodyRef.current.scrollTo({top: chatBodyRef.current.scrollHeight, behavior: "smooth"});
  }, [chatHistory]);

  return (
    <div className={`container ${showChatbot ? "show-chatbot" : ""}`}>
        <button onClick={() => setShowChatbot((prev) => !prev)} id="chatbot-toggler">
          <span className="material-symbols-rounded">mode_comment</span>
          <span className="material-symbols-rounded">close</span>
        </button>

        <div className="chatbot-popup">
          {/* Chatbot Header */}
            <div className="chat-header">
                <div className="header-info">
                    <ChatbotIcon />
                    <h2 className="logo-text">Chatbot</h2>
                </div>
                <button onClick={() => setShowChatbot((prev) => !prev)}
                className="material-symbols-rounded">keyboard_arrow_down</button>
            </div>

          {/* Chatbot Body */}
            <div ref={chatBodyRef} className="chat-body">
              <div className="message bot-message">
                <ChatbotIcon />
                <p className="message-text">
                  Hey there 👋 <br /> How can I help you today?
                </p>
              </div>

              {/* Render the chat history dinamically */}
              {chatHistory.map((chat, index) => (
                <ChatMessage key={index} chat={chat}/>
              ))}
              
            </div>
            {/* Chatbot Footer */}
            <div className="chat-footer">
              <ChatForm chatHistory={chatHistory} setChatHistory={setChatHistory} generateBotResponse={generateBotResponse}/>

            </div>
        </div>
    </div>
  );
};

export default App;