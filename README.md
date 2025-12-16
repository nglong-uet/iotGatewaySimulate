 git clone https://github.com/PigCassoKien/iotGatewaySimulate.git
Đảm bảo đã tải docker, kiểm tra bằng lệnh: 
docker version
- cd gateway
- docker build -t iot-gateway .   
- docker run -d --name iot-gateway --add-host=host.docker.internal:host-gateway iot-gateway
- vào docker xem log của container iot-gateway 
