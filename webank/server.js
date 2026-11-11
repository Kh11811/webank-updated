const app = require('./src/app');
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`WeBank demo running on http://localhost:${port}`);
  console.log('Demo customer: demo@webank.demo / Demo#WeBank2026');
});
