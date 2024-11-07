const express = require('express');
const app = express();

app.use(express.json()); //This middleware is used to parse JSON bodies

//GET route
app.get('/api/items', (req, res) => {
    res.send('List of items');
});

app.post('/api/items', (req,res) => {
    const newItem = req.body;
    res.send('Item added: ${newItem.name}');
});

app.put('/api/items/:id', (req,res) => {
    const itemId = req.params.id;
    res.send(`Item with ID ${itemId} updated`);
});

app.delete('/api/items/:id', (req,res) => {
    const itemId = req.params.id;
    res.send(`Item with ID ${itemId} deleted`);
});

app.listen(3000, () => console.log('Server running on port 3000'));