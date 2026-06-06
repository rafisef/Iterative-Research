std::string searchTerm = userInput;
std::string query = "SELECT * FROM products WHERE name LIKE ?";
stmt->setString(1, "%" + searchTerm + "%");