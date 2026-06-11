module.exports = async function workerTimeoutTool() {
  await new Promise(() => {
    setInterval(() => {}, 1000);
  });
};
