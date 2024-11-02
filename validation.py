import requests, math
from flask import request

# 유저 위치 가져오기
def get_user_location(ip_adrress):
    try:
        google_maps_api_key = "AIzaSyASdR4wWNv9LpEOMTIdyz6capGBNzZAZlE"
        if not google_maps_api_key:
            raise ValueError("Google Maps API 키를 찾을 수 없습니다.")
        
        # Google Geolocation API를 사용하여 사용자의 위치 가져오기
        url = f'https://www.googleapis.com/geolocation/v1/geolocate?key={google_maps_api_key}'
        response = requests.post(url)
        data = response.json()
        
        location = data.get('location')
        if location:
            latitude = location.get('lat')
            longitude = location.get('lng')
            return latitude, longitude
        else:
            print("위치 정보를 가져올 수 없습니다.")
            return None, None
    except Exception as e:
        print(f"오류 발생: {e}")
        return None, None
    
# 거리 계산
def calculate_distance(lat1, lon1, lat2, lon2):
    # 지구의 반지름 (단위: km)
    R = 6371.0
    
    # 라디안 변환
    lat1 = math.radians(lat1)
    lon1 = math.radians(lon1)
    lat2 = math.radians(lat2)
    lon2 = math.radians(lon2)
    
    # 위도와 경도 차이 계산
    dlon = lon2 - lon1
    dlat = lat2 - lat1
    
    # 허츠 공식 계산
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    
    # 거리 계산
    distance = R * c
    return distance

# User IP 주소와 가장 가까운 도시 찾기
def find_closest_city(client_ip, cities):
    client_ip = request.remote_addr
    user_lat, user_lon = get_user_location(client_ip)
 
    print(f"Client IP: {client_ip}, Latitude: {user_lat}, Longitude: {user_lon}")
    closest_city = None
    min_distance = float('inf')
    for city in cities:
        city_lat, city_lon = city['lat'], city['lon']
        distance = calculate_distance(user_lat, user_lon, city_lat, city_lon)
        if distance < min_distance:
            min_distance = distance
            closest_city = city['name']
    return closest_city

    