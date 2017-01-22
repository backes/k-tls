/*
 * indexer.cpp
 *
 *  Created on: Jun 18, 2014
 *      Author: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 */

#include "indexer.h"

#include <cstring>
#include <iostream>

namespace { // anonymous

enum TokenType {
    IDENTIFIER,
    EQUALS,
    VOID,
    INT,
    INT_CONSTANT,
    COMMA,
    OPEN_PAREN,
    CLOSE_PAREN,
    OPEN_BRACE,
    CLOSE_BRACE,
    SEMICOLON,
    _EOF
};

struct Token {
    TokenType type;
    unsigned lineNr;
    unsigned colNr;
    char *pos;
    size_t len;

    Token(): type(_EOF), lineNr(0), colNr(0), pos(0), len(0) { }
    Token(TokenType type, unsigned lineNr, unsigned colNr, char *pos, size_t len)
    : type(type), lineNr(lineNr), colNr(colNr), pos(pos), len(len) { }
};

class Lexer {
    MyString filename;
    char *pos;
    char *end;
    unsigned lineNr;
    char *lineStart;

    Token _lastToken;
    Token _nextToken;

    MyVector<ParseError> &parseErrors;

    Token makeToken(TokenType type, char *start) {
        return _lastToken = Token(type, lineNr, start - lineStart + 1, start, pos - start);
    }

    TRANSACTION_SAFE
    Token genToken() {
        if (_nextToken.pos) {
            _lastToken = _nextToken;
            _nextToken.pos = 0;
            return _lastToken;
        }

        // skip whitespaces
        while (pos < end) {
            if (*pos == '\n') {
                ++lineNr;
                lineStart = pos+1;
            } else if (*pos != ' ' && *pos != '\r' && *pos != '\t')
                break;
            ++pos;
        }

        if (pos == end)
            return makeToken(_EOF, pos);

        char *start = pos;
        switch (*pos++) {
        case '=': return makeToken(EQUALS, start);
        case ',': return makeToken(COMMA, start);
        case ';': return makeToken(SEMICOLON, start);
        case '(': return makeToken(OPEN_PAREN, start);
        case ')': return makeToken(CLOSE_PAREN, start);
        case '{': return makeToken(OPEN_BRACE, start);
        case '}': return makeToken(CLOSE_BRACE, start);

        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            while (pos < end && (*pos >= '0' && *pos <= '9'))
                ++pos;
            return makeToken(INT_CONSTANT, start);

        default:
            if ((*pos < 'a' || *pos > 'z') && (*pos < 'A' && *pos > 'Z')) {
                parseErrors.push_back(ParseError(getLocation(makeToken(_EOF, pos)),
                        "Illegal character"));
                return makeToken(_EOF, pos);
            }

            while (pos < end && (
                    (*pos >= 'a' && *pos <= 'z') ||
                    (*pos >= '0' && *pos <= '9') ||
                    *pos == '-' || *pos == '_'))
                ++pos;
            size_t len = pos - start;
            TokenType type = IDENTIFIER;
            if (len == 3 && cmpStr(start, "int", 3))
                type = INT;
            else if (len == 4 && cmpStr(start, "void", 4))
                type = VOID;
            return makeToken(type, start);
        }
    }

public:
    Lexer(const Mapping &mapping, MyVector<ParseError> &parseErrors)
    : filename(mapping.filename), pos(mapping.start),
      end(mapping.start + mapping.len), lineNr(1), lineStart(pos),
      parseErrors(parseErrors)
    { }

    TRANSACTION_SAFE
    Location getLocation(Token token) {
        return Location(filename.data, filename.len, token.lineNr, token.colNr);
    }

    TokenType nextType() {
        return genToken().type;
    }

    TokenType peekType() {
        return peekToken().type;
    }

    TRANSACTION_SAFE
    Token peekToken() {
        if (_nextToken.pos == 0)
            _nextToken = genToken();
        return _nextToken;
    }

    Token nextToken() {
        return genToken();
    }

    Token lastToken() {
        return _lastToken;
    }

    void putBackToken(Token token) {
        if (_nextToken.pos) {
            std::cerr << "Internal error: cannot put back more than one token!" << std::endl;
            exit(1);
        }
        _nextToken = std::move(token);
    }
};

class Parser {
    Lexer lexer;
    SymbolRepo &repo;
    MyVector<ParseError> &parseErrors;

public:
    Parser(const Mapping &mapping, SymbolRepo &repo, MyVector<ParseError> &parseErrors)
    : lexer(mapping, parseErrors), repo(repo), parseErrors(parseErrors) { }

    TRANSACTION_SAFE
    bool printError(Token pos, const char *message) {
        parseErrors.push_back(ParseError(lexer.getLocation(pos), message));
        return true;
    }

    TRANSACTION_SAFE
    bool parseType() {
        switch (lexer.nextType()) {
        case INT:
        case VOID:
            break;
        default:
            return printError(lexer.lastToken(), "Expecting 'int' or 'void'");
            break;
        }
        return false;
    }

    TRANSACTION_SAFE
    bool parseIdentifier() {
        if (lexer.nextType() != IDENTIFIER)
            return printError(lexer.lastToken(), "Expecting identifier");
        return false;
    }

    TRANSACTION_SAFE
    bool parseValue() {
        Token firstToken = lexer.nextToken();
        Type type = VARIABLE;
        switch (firstToken.type) {
        case INT_CONSTANT:
            break;
        case IDENTIFIER:
            if (lexer.peekType() == OPEN_PAREN) {
                lexer.nextToken();
                // function call
                if (lexer.peekType() != CLOSE_PAREN) {
                    if (parseValue())
                        return true;
                    while (lexer.peekType() == COMMA) {
                        lexer.nextToken();
                        if (parseValue())
                            return true;
                    }
                }
                if (lexer.nextType() != CLOSE_PAREN)
                    return printError(lexer.lastToken(), "Expecting ')'");
                type = FUNCTION;
            }
            // and store this symbol use
            repo.addUse(Symbol(firstToken.pos, firstToken.len, type),
                    lexer.getLocation(firstToken));
            break;
        default:
            return printError(firstToken, "Expecting a value (integer, identifier or function call)");
        }
        return false;
    }

    TRANSACTION_SAFE
    bool parseDeclaration() {
        if (parseType())
            return true;
        Token identifierToken = lexer.peekToken();
        if (parseIdentifier())
            return true;
        switch (lexer.nextType()) {
        default:
            return printError(lexer.lastToken(),
                    "Expecting ';', '=' or '(' for variable or function declaration");
        case EQUALS: // var-declaration (with initialization)
            if (parseValue())
                return true;
            if (lexer.nextType() != SEMICOLON)
                return printError(lexer.lastToken(), "Expecting ';' after variable declaration");
            // fall-through
        case SEMICOLON: // var-declaration (without initialization)
            repo.addDefinition(Symbol(identifierToken.pos, identifierToken.len,
                    VARIABLE), lexer.getLocation(identifierToken));
            break;
        case OPEN_PAREN: // func-declaration or func-definition

            // parse the param list:
            if (lexer.peekType() == VOID || lexer.peekType() == INT) {
                if (parseType())
                    return true;
                if (lexer.peekType() == IDENTIFIER)
                    if (parseIdentifier())
                        return true;
                while (lexer.peekType() == COMMA) {
                    lexer.nextToken();
                    if (parseType())
                        return true;
                    if (lexer.peekType() == IDENTIFIER)
                        if (parseIdentifier())
                            return true;
                }
            }

            if (lexer.nextType() != CLOSE_PAREN)
                return printError(lexer.lastToken(), "Expecting ')' after parameter list");

            switch (lexer.nextType()) {
            default:
                return printError(lexer.lastToken(),
                        "Expecting '{' or ';' for function declaration or definition");
                break;
            case OPEN_BRACE:
                // func-definition
                while (lexer.peekType() != CLOSE_BRACE) {
                    return parseStatement();
                }
                if (lexer.nextType() != CLOSE_BRACE)
                    return printError(lexer.lastToken(), "Expecting '}' to finish function body");
            case SEMICOLON:
                break;
            }

            // and record this declaration/definition:
            repo.addDefinition(Symbol(identifierToken.pos, identifierToken.len,
                    FUNCTION), lexer.getLocation(identifierToken));
            break;
        }
        return false;
    }

    TRANSACTION_SAFE
    bool parseStatement() {
        if (lexer.peekType() == VOID || lexer.peekType() == INT) {
            return parseDeclaration();
        } else {
            if (parseValue())
                return true;
            if (lexer.nextType() != SEMICOLON)
                return printError(lexer.lastToken(), "Expecting ';' to finish statement");
            return false;
        }
    }

    TRANSACTION_SAFE
    bool parseProgram() {
        while (lexer.peekType() != _EOF) {
            if (parseDeclaration())
                return true;
        }
        return false;
    }

};

} // anonymous namespace

void Indexer::indexFile(const Mapping &mapping, MyVector<ParseError> &parseErrors) {
    /* we parse the following:
     *    program          := declaration*
     *    declaration      := var-declaration | func-declaration | func-definition
     *    var-declaration  := type identifier [ '=' value ] ';'
     *    func-prototype   := type identifier '(' [ param [ ',' param ]* ]? ')'
     *    func-declaration := func-prototype ';'
     *    func-definition  := func-prototype '{' [ statement ';' ]* '}'
     *    statement        := declaration | [ value ';' ]
     *    value            := int-const | identifier | func-call
     *    func-call        := identifier '(' [ value [ ',' value ]* ]? ')'
     *    param            := type identifier?
     *    type             := 'int' | 'void'
     *    identifier       := ['a'..'z' | 'A'..'Z'] ['a'..'z' | 'A'..'Z' | '0'..'9' | '-' | '_']*
     *    int-const        := ['0'..'9']+
     */
    Parser parser(mapping, repo, parseErrors);
    parser.parseProgram();
}


